//! Transparent UDP provenance, bounded admission, and receive-loop dispatch.

use super::udp_endpoint::{DatagramPayload, RawDnsRoute};
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct UdpOriginalDst {
    pub(super) address: SocketAddr,
    pub(super) validated_dns: Option<ValidatedDnsQuery>,
}

/// ORIGDST is authoritative; only an exact DNS query may recover port 53
/// from PKTINFO. A wildcard bind never supplies a missing destination.
pub(super) fn udp_original_dst(meta: &UdpRecvMeta, data: &[u8]) -> Option<UdpOriginalDst> {
    if let Some(original_dst) = meta.original_dst_cmsg {
        return (!original_dst.ip().is_unspecified()).then_some(UdpOriginalDst {
            address: original_dst,
            validated_dns: None,
        });
    }
    let validated_dns = validate_exact_dns_query(data);
    if let Some(validated_dns) = validated_dns
        && let Some(packet_dst_ip) = meta.packet_dst_ip
        && !packet_dst_ip.is_unspecified()
    {
        return Some(UdpOriginalDst {
            address: SocketAddr::new(packet_dst_ip, 53),
            validated_dns: Some(validated_dns),
        });
    }
    (!meta.local_addr.ip().is_unspecified()).then_some(UdpOriginalDst {
        address: meta.local_addr,
        validated_dns,
    })
}

/// Owns admitted work after routing publication guards have been released.
pub(super) enum UdpSlowPathWork {
    Initialize(UdpInitLease),
    #[cfg(feature = "ebpf")]
    QueuedDatagram {
        data: Bytes,
        raw_dns_route: Option<RawDnsRoute>,
        expected_epoch: u64,
        enqueued_at: u32,
        permit: tokio::sync::OwnedSemaphorePermit,
    },
    Dns {
        admission: crate::control::dns_control::AdmittedDnsQuery,
        data: Bytes,
        validated: ValidatedDnsQuery,
    },
    DnsRefused {
        runtime: crate::dns::runtime::RuntimeLease,
        udp_permit: tokio::sync::OwnedSemaphorePermit,
        response: Vec<u8>,
    },
    Done,
}

#[cfg(test)]
pub(super) fn begin_udp_slow_path(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    dns: Option<(
        &crate::control::dns_control::DnsController,
        ValidatedDnsQuery,
    )>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
) -> UdpSlowPathWork {
    begin_udp_slow_path_at(
        pool,
        stats,
        concurrency_limit,
        dns,
        src_addr,
        original_dst,
        data,
        None,
        pool.initialization_epoch(),
        udp_endpoint::queue_now(),
    )
}

/// Query and endpoint admission both precede payload retention.
#[allow(clippy::too_many_arguments)]
pub(super) fn begin_udp_slow_path_at(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    dns: Option<(
        &crate::control::dns_control::DnsController,
        ValidatedDnsQuery,
    )>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    raw_dns_route: Option<RawDnsRoute<&str>>,
    expected_epoch: u64,
    enqueued_at: u32,
) -> UdpSlowPathWork {
    if original_dst.port() == 53
        && let Some((dns_controller, validated)) = dns
    {
        return begin_udp_dns_query(
            dns_controller,
            stats,
            DatagramPayload::Borrowed(data),
            validated,
        );
    }
    let Some(permit) = try_admit_udp_slow_path(stats, concurrency_limit) else {
        return UdpSlowPathWork::Done;
    };
    match pool.reserve_or_enqueue_at(
        src_addr,
        original_dst,
        data,
        raw_dns_route,
        expected_epoch,
        permit,
        enqueued_at,
        stats,
    ) {
        EndpointReservation::Initializing(lease) => UdpSlowPathWork::Initialize(lease),
        EndpointReservation::Enqueued
        | EndpointReservation::CapacityRejected
        | EndpointReservation::QueueFull
        | EndpointReservation::IdentityMismatch
        | EndpointReservation::QueueClosed => UdpSlowPathWork::Done,
    }
}

fn begin_udp_dns_query(
    dns_controller: &crate::control::dns_control::DnsController,
    stats: &StatsManager,
    data: DatagramPayload<'_>,
    validated: ValidatedDnsQuery,
) -> UdpSlowPathWork {
    let admission = match dns_controller.try_admit_query(true) {
        Ok(admission) => {
            stats.record_udp_slow_permit_accepted();
            admission
        }
        Err(error) => {
            if let Some((runtime, udp_permit)) = error.udp_reply {
                stats.record_udp_slow_permit_accepted();
                return UdpSlowPathWork::DnsRefused {
                    runtime,
                    udp_permit,
                    response: crate::dns::response::build_dns_refused(data.as_slice()),
                };
            }
            stats.record_udp_slow_permit_rejected();
            return UdpSlowPathWork::Done;
        }
    };
    UdpSlowPathWork::Dns {
        admission,
        data: data.into_bytes(),
        validated,
    }
}

#[derive(Clone)]
pub(super) struct UdpLoopState {
    pub(super) udp_pool: Arc<UdpEndpointPool>,
    pub(super) stats: Arc<StatsManager>,
    pub(super) udp_concurrency_limit: Arc<tokio::sync::Semaphore>,
    pub(super) dns_controller: Arc<crate::control::dns_control::DnsController>,
    pub(super) drain: Arc<DrainTracker>,
    pub(super) requires_dns_route_mark: bool,
    pub(super) handle: ControlPlaneHandle,
}

impl UdpLoopState {
    pub(super) fn new(plane: &ControlPlane, requires_dns_route_mark: bool) -> Self {
        Self {
            udp_pool: Arc::clone(&plane.udp_pool),
            stats: Arc::clone(&plane.stats),
            udp_concurrency_limit: Arc::clone(&plane.udp_concurrency_limit),
            dns_controller: Arc::clone(&plane.dns_controller),
            drain: Arc::clone(&plane.drain_tracker),
            requires_dns_route_mark,
            handle: plane.spawn_handle(),
        }
    }

    pub(super) async fn dispatch_datagram_at(
        &self,
        data: &[u8],
        src_addr: SocketAddr,
        recv_meta: &UdpRecvMeta,
        enqueued_at: u32,
    ) {
        let destination = if self.requires_dns_route_mark {
            recv_meta
                .original_dst_cmsg
                .filter(|address| !address.ip().is_unspecified())
                .map(|address| UdpOriginalDst {
                    address,
                    validated_dns: None,
                })
        } else {
            udp_original_dst(recv_meta, data)
        };
        let Some(destination) = destination else {
            debug!(%src_addr, "Dropping UDP without original-destination provenance");
            return;
        };
        let original_dst = destination.address;
        let work = if self.requires_dns_route_mark && original_dst.port() == 53 {
            let Some(route) = recv_meta.packet_mark.and_then(UdpDnsRoute::from_mark) else {
                debug!(%src_addr, %original_dst, "Dropping UDP/53 without a valid route mark");
                return;
            };
            self.admit_routed_dns_at(
                DatagramPayload::Borrowed(data),
                src_addr,
                original_dst,
                route,
                enqueued_at,
            )
            .await
        } else {
            let validated_dns = if original_dst.port() == 53 {
                destination
                    .validated_dns
                    .or_else(|| validate_exact_dns_query(data))
            } else {
                destination.validated_dns
            };
            self.admit_datagram_at(
                data,
                src_addr,
                original_dst,
                validated_dns,
                None,
                None,
                enqueued_at,
            )
        };
        self.spawn_work(src_addr, original_dst, work);
    }

    pub(super) async fn admit_routed_dns_at(
        &self,
        data: DatagramPayload<'_>,
        src_addr: SocketAddr,
        original_dst: SocketAddr,
        route: UdpDnsRoute,
        enqueued_at: u32,
    ) -> UdpSlowPathWork {
        let expected_epoch = self.udp_pool.initialization_epoch();
        // Match reload's router -> config -> backend publication order.
        let router = if route.direct_mark_index().is_some() {
            Some(self.handle.router.read().await)
        } else {
            None
        };
        let config = self.handle.config.read().await;
        let backend = self.handle.ebpf.read().await;
        if backend.routing_policy_generation() != u64::from(route.generation()) {
            debug!(%src_addr, %original_dst, packet_generation = route.generation(),
                "Dropping UDP/53 from a stale routing generation");
            return UdpSlowPathWork::Done;
        }
        let raw_dns_route = if let Some(index) = route.direct_mark_index() {
            let Some(mark) = router.as_ref().and_then(|router| router.direct_mark(index)) else {
                debug!(%src_addr, %original_dst, index, "Dropping UDP/53 with no direct mark owner");
                return UdpSlowPathWork::Done;
            };
            Some(RawDnsRoute::Direct(mark))
        } else if route.outbound() == OutboundIndex::ControlPlaneRouting as u8 {
            None
        } else {
            let Some(group) = route
                .outbound()
                .checked_sub(OutboundIndex::UserBase as u8)
                .and_then(|index| config.groups.get(index as usize))
            else {
                debug!(%src_addr, %original_dst, outbound = route.outbound(),
                    "Dropping UDP/53 with no current route owner");
                return UdpSlowPathWork::Done;
            };
            Some(RawDnsRoute::Group(group.name.as_str()))
        };
        drop(backend);
        if self.drain.should_reject() || !self.udp_pool.initialization_epoch_is(expected_epoch) {
            self.stats.record_udp_slow_permit_closed();
            return UdpSlowPathWork::Done;
        }
        if udp_ingress_excluded(src_addr, original_dst) {
            return UdpSlowPathWork::Done;
        }
        let validated_dns = raw_dns_route
            .is_none()
            .then(|| validate_exact_dns_query(data.as_slice()))
            .flatten();
        // Config remains guarded through synchronous admission, not through spawned I/O.
        if let Some(validated) = validated_dns {
            return begin_udp_dns_query(&self.dns_controller, &self.stats, data, validated);
        }
        match data {
            DatagramPayload::Borrowed(data) => self.admit_datagram_at(
                data,
                src_addr,
                original_dst,
                None,
                raw_dns_route,
                Some(expected_epoch),
                enqueued_at,
            ),
            #[cfg(feature = "ebpf")]
            DatagramPayload::Owned(data) => {
                let Some(permit) =
                    try_admit_udp_slow_path(&self.stats, &self.udp_concurrency_limit)
                else {
                    return UdpSlowPathWork::Done;
                };
                // Ready endpoints can send immediately: retain privately until NF_DROP succeeds.
                UdpSlowPathWork::QueuedDatagram {
                    data,
                    raw_dns_route: raw_dns_route.map(RawDnsRoute::into_owned),
                    expected_epoch,
                    enqueued_at,
                    permit,
                }
            }
            #[cfg(all(test, not(feature = "ebpf")))]
            DatagramPayload::Owned(_) => unreachable!("queued DNS requires NFQUEUE"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_datagram_at(
        &self,
        data: &[u8],
        src_addr: SocketAddr,
        original_dst: SocketAddr,
        validated_dns: Option<ValidatedDnsQuery>,
        raw_dns_route: Option<RawDnsRoute<&str>>,
        expected_epoch: Option<u64>,
        enqueued_at: u32,
    ) -> UdpSlowPathWork {
        if self.drain.should_reject()
            || expected_epoch.is_some_and(|epoch| !self.udp_pool.initialization_epoch_is(epoch))
        {
            self.stats.record_udp_slow_permit_closed();
            return UdpSlowPathWork::Done;
        }
        if udp_fast_path_at(
            &self.udp_pool,
            &self.stats,
            data,
            src_addr,
            original_dst,
            validated_dns,
            raw_dns_route,
            enqueued_at,
        ) {
            return UdpSlowPathWork::Done;
        }
        begin_udp_slow_path_at(
            &self.udp_pool,
            &self.stats,
            &self.udp_concurrency_limit,
            validated_dns.map(|validated| (self.dns_controller.as_ref(), validated)),
            src_addr,
            original_dst,
            data,
            raw_dns_route,
            expected_epoch.unwrap_or_else(|| self.udp_pool.initialization_epoch()),
            enqueued_at,
        )
    }

    pub(super) fn spawn_work(
        &self,
        src_addr: SocketAddr,
        original_dst: SocketAddr,
        work: UdpSlowPathWork,
    ) {
        match work {
            UdpSlowPathWork::Done => {}
            #[cfg(feature = "ebpf")]
            UdpSlowPathWork::QueuedDatagram {
                data,
                raw_dns_route,
                expected_epoch,
                enqueued_at,
                permit,
            } => {
                if self.drain.should_reject()
                    || !self.udp_pool.initialization_epoch_is(expected_epoch)
                {
                    self.stats.record_udp_slow_permit_closed();
                    return;
                }
                if let EndpointReservation::Initializing(lease) =
                    self.udp_pool.reserve_payload_or_enqueue_at(
                        src_addr,
                        original_dst,
                        DatagramPayload::Owned(data),
                        raw_dns_route.as_ref().map(RawDnsRoute::as_ref),
                        expected_epoch,
                        permit,
                        enqueued_at,
                        &self.stats,
                    )
                {
                    self.spawn_work(src_addr, original_dst, UdpSlowPathWork::Initialize(lease));
                }
            }
            UdpSlowPathWork::Initialize(lease) => {
                let handle = self.handle.clone();
                let guard = ConnectionGuard::new(Arc::clone(&self.drain));
                self.udp_pool.spawn_slow_path(async move {
                    let _guard = guard;
                    if let Err(error) = handle.serve_udp_connection(lease).await {
                        warn!(%src_addr, %original_dst, %error, "Error handling UDP");
                    }
                });
            }
            UdpSlowPathWork::Dns {
                admission,
                data,
                validated,
            } => {
                let guard = ConnectionGuard::new(Arc::clone(&self.drain));
                let dns_controller = Arc::clone(&self.dns_controller);
                self.udp_pool.spawn_slow_path(async move {
                    let _guard = guard;
                    dns_controller
                        .handle_udp_dns_admitted(
                            &admission,
                            &data,
                            src_addr,
                            original_dst,
                            validated,
                        )
                        .await;
                });
            }
            UdpSlowPathWork::DnsRefused {
                runtime,
                udp_permit,
                response,
            } => {
                let guard = ConnectionGuard::new(Arc::clone(&self.drain));
                self.udp_pool.spawn_slow_path(async move {
                    let _guard = guard;
                    let _permit = udp_permit;
                    let _ = runtime
                        .run_reply(send_udp_reply_from_orig_dst(
                            &response,
                            src_addr,
                            original_dst,
                        ))
                        .await;
                });
            }
        }
    }
}

pub(super) async fn udp_listener_loop(
    state: UdpLoopState,
    socket: Arc<UdpSocket>,
    family: &'static str,
) {
    let mut batch = match UdpRecvBatch::new() {
        Ok(batch) => batch,
        Err(error) => {
            error!(family, %error, "UDP receive setup failed");
            return;
        }
    };
    let local_addr = match socket.local_addr() {
        Ok(address) => address,
        Err(error) => {
            error!(family, %error, "UDP listener address unavailable");
            return;
        }
    };
    loop {
        if let Err(error) = recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch).await {
            error!(family, %error, "UDP receive failed");
            continue;
        }
        let enqueued_at = udp_endpoint::queue_now();
        for index in 0..batch.len() {
            let (data, src_addr, metadata) = match batch.packet(index) {
                Ok(packet) => packet,
                Err(error) => {
                    error!(family, %error, "Invalid UDP receive metadata");
                    continue;
                }
            };
            state
                .dispatch_datagram_at(data, src_addr, &metadata, enqueued_at)
                .await;
        }
    }
}

#[cfg(test)]
pub(super) fn dispatch_udp_slow_path(
    state: &UdpLoopState,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    validated_dns: Option<ValidatedDnsQuery>,
) {
    let work = begin_udp_slow_path(
        &state.udp_pool,
        &state.stats,
        &state.udp_concurrency_limit,
        validated_dns.map(|validated| (state.dns_controller.as_ref(), validated)),
        src_addr,
        original_dst,
        data,
    );
    state.spawn_work(src_addr, original_dst, work);
}

#[cfg(test)]
pub(super) fn reserve_udp_slow_path(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
) -> Option<UdpInitLease> {
    match begin_udp_slow_path(
        pool,
        stats,
        concurrency_limit,
        None,
        src_addr,
        original_dst,
        data,
    ) {
        UdpSlowPathWork::Initialize(lease) => Some(lease),
        #[cfg(feature = "ebpf")]
        UdpSlowPathWork::QueuedDatagram { .. } => {
            unreachable!("socket admission cannot produce queued-only work")
        }
        UdpSlowPathWork::Dns { .. }
        | UdpSlowPathWork::DnsRefused { .. }
        | UdpSlowPathWork::Done => None,
    }
}

pub(super) fn try_admit_udp_slow_path(
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    match concurrency_limit.clone().try_acquire_owned() {
        Ok(permit) => {
            stats.record_udp_slow_permit_accepted();
            Some(permit)
        }
        Err(_) => {
            stats.record_udp_slow_permit_rejected();
            None
        }
    }
}

#[cfg(test)]
pub(super) fn udp_fast_path(
    udp_pool: &UdpEndpointPool,
    stats: &StatsManager,
    data: &[u8],
    client_addr: SocketAddr,
    original_dst: SocketAddr,
    validated_dns: Option<ValidatedDnsQuery>,
) -> bool {
    udp_fast_path_at(
        udp_pool,
        stats,
        data,
        client_addr,
        original_dst,
        validated_dns,
        None,
        udp_endpoint::queue_now(),
    )
}

fn udp_ingress_excluded(client_addr: SocketAddr, original_dst: SocketAddr) -> bool {
    if is_honk_internal_addr(&original_dst.ip()) || is_honk_internal_addr(&client_addr.ip()) {
        trace!(%client_addr, %original_dst, "Skipping honk-internal UDP");
        return true;
    }
    if is_broadcast_or_multicast(&original_dst.ip()) {
        trace!(%client_addr, %original_dst, "Skipping broadcast/multicast UDP");
        return true;
    }
    false
}

/// Ready hits only enqueue under existing byte/packet permits; transport I/O
/// stays with the endpoint driver and valid DNS keeps its separate query budget.
#[allow(clippy::too_many_arguments)]
fn udp_fast_path_at(
    udp_pool: &UdpEndpointPool,
    stats: &StatsManager,
    data: &[u8],
    client_addr: SocketAddr,
    original_dst: SocketAddr,
    validated_dns: Option<ValidatedDnsQuery>,
    raw_dns_route: Option<RawDnsRoute<&str>>,
    enqueued_at: u32,
) -> bool {
    if udp_ingress_excluded(client_addr, original_dst) {
        return true;
    }
    if original_dst.port() == 53 && validated_dns.is_some() {
        return false;
    }
    let Some(result) = udp_pool.fast_path_enqueue_at(
        client_addr,
        original_dst,
        data,
        raw_dns_route,
        enqueued_at,
        stats,
    ) else {
        stats.record_udp_endpoint_miss();
        return false;
    };
    if matches!(
        result,
        EndpointReservation::QueueClosed | EndpointReservation::IdentityMismatch
    ) {
        return true;
    }
    stats.record_udp_endpoint_hit();
    debug!(%client_addr, %original_dst, "UDP endpoint enqueue");
    debug_assert!(matches!(
        result,
        EndpointReservation::Enqueued | EndpointReservation::QueueFull
    ));
    true
}

#[cfg(test)]
mod tests;
