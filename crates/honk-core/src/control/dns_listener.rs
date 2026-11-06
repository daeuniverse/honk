//! Process-scoped standalone DNS listener for `dns.bind`.
//!
//! These sockets are ordinary host-netns listeners. They deliberately do not
//! carry proxy marks and never enter `daens`; only the transparent port-53
//! listeners use that machinery.

use super::ConnectionGuard;
use crate::control::dns_control::DnsController;
use crate::control::drain::DrainTracker;
use crate::dns::query::{DnsRequestMeta, validate_exact_dns_query};
use crate::stats::StatsManager;
use honk_config::dns::DnsBindEndpoint;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::task::Poll;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info};

const EPHEMERAL_BIND_ATTEMPTS: usize = 32;
const fn standalone_tcp_capacity(total_connection_capacity: usize) -> usize {
    if total_connection_capacity == 0 {
        0
    } else {
        let quarter = total_connection_capacity / 4;
        if quarter == 0 { 1 } else { quarter }
    }
}

fn minimal_dns_error_response(query: &[u8], rcode: u8) -> [u8; 12] {
    let mut response = [0u8; 12];
    if let Some(txid) = query.get(..2) {
        response[..2].copy_from_slice(txid);
    }
    response[2..4]
        .copy_from_slice(&crate::dns::response::dns_error_flags(query, rcode).to_be_bytes());
    response
}

fn enable_bound_udp_packet_info(socket: &std::net::UdpSocket, is_v6: bool) -> io::Result<()> {
    if is_v6 {
        nix::sys::socket::setsockopt(socket, nix::sys::socket::sockopt::Ipv6RecvPacketInfo, &true)
            .map_err(io::Error::from)
    } else {
        nix::sys::socket::setsockopt(socket, nix::sys::socket::sockopt::Ipv4PacketInfo, &true)
            .map_err(io::Error::from)
    }
}

fn udp_response_source(meta: &super::sockets::UdpRecvMeta) -> Option<(IpAddr, u32)> {
    meta.packet_dst_ip
        .filter(|ip| !ip.is_unspecified())
        .map(|ip| (ip, meta.packet_ifindex.unwrap_or(0)))
        .or_else(|| (!meta.local_addr.ip().is_unspecified()).then_some((meta.local_addr.ip(), 0)))
}

async fn send_bound_udp_response(
    socket: &UdpSocket,
    response: &[u8],
    response_source: (IpAddr, u32),
    client_addr: SocketAddr,
) -> io::Result<usize> {
    super::sockets::send_to_with_src(
        socket,
        response,
        response_source.0,
        response_source.1,
        client_addr,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerPhase {
    Running,
    StopAccepting,
    Abort,
}

/// Synchronously bound sockets. Keeping binding separate from spawning makes
/// dual-transport startup atomic: no supervisor exists until every selected
/// socket has successfully bound.
pub(super) struct BoundDnsListener {
    tcp: Option<std::net::TcpListener>,
    udp: Option<std::net::UdpSocket>,
    #[cfg(test)]
    local_addr: SocketAddr,
}

impl BoundDnsListener {
    pub(super) fn bind(endpoint: &DnsBindEndpoint) -> io::Result<Self> {
        let candidates = resolve_bind_addresses(endpoint)?;
        let mut last_error = None;

        for candidate in candidates {
            let attempts =
                if candidate.port() == 0 && endpoint.tcp_enabled() && endpoint.udp_enabled() {
                    EPHEMERAL_BIND_ATTEMPTS
                } else {
                    1
                };
            for _ in 0..attempts {
                match bind_selected(candidate, endpoint.tcp_enabled(), endpoint.udp_enabled()) {
                    Ok(bound) => return Ok(bound),
                    Err(error) => last_error = Some(error),
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "dns.bind resolved to no usable address",
            )
        }))
    }

    pub(super) fn spawn(
        self,
        controller: Arc<DnsController>,
        connection_limit: Arc<Semaphore>,
        stats: Arc<StatsManager>,
        drain: Arc<DrainTracker>,
        native: Option<Arc<crate::observe::Observation>>,
        diagnostics: crate::config_diagnostics::SharedDiagnostics,
    ) -> io::Result<DnsListener> {
        let Self { tcp, udp, .. } = self;
        let address = match (&tcp, &udp) {
            (Some(listener), _) => Some(listener.local_addr()?),
            (None, Some(socket)) => Some(socket.local_addr()?),
            (None, None) => None,
        };
        let udp = udp.map(UdpSocket::from_std).transpose()?.map(Arc::new);
        let tcp = tcp.map(TcpListener::from_std).transpose()?;
        // The release smoke keys on this message. The native log feed admits it only
        // as a literal `message` field at the runtime target it had before this move.
        if let Some(address) = address {
            tracing::info!(
                target: "honk_core::control::runtime",
                %address,
                tcp = tcp.is_some(),
                udp = udp.is_some(),
                message = "Standalone DNS listener started"
            );
        }
        let (phase, phase_rx) = watch::channel(ListenerPhase::Running);
        let standalone_tcp_limit = Arc::new(Semaphore::new(standalone_tcp_capacity(
            connection_limit.available_permits(),
        )));
        let mut supervisors = JoinSet::new();

        if let Some(socket) = udp {
            for _ in 0..tokio::runtime::Handle::current()
                .metrics()
                .num_workers()
                .clamp(1, 4)
            {
                supervisors.spawn(run_udp_supervisor(
                    Arc::clone(&socket),
                    Arc::clone(&controller),
                    Arc::clone(&stats),
                    Arc::clone(&drain),
                    phase_rx.clone(),
                    native.clone(),
                    diagnostics.clone(),
                ));
            }
        }
        if let Some(listener) = tcp {
            supervisors.spawn(run_tcp_supervisor(
                listener,
                controller,
                connection_limit,
                standalone_tcp_limit,
                drain,
                phase_rx,
                #[cfg(feature = "native-api")]
                native,
                #[cfg(feature = "native-api")]
                diagnostics,
            ));
        }

        Ok(DnsListener { phase, supervisors })
    }

    #[cfg(test)]
    pub(super) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[cfg(test)]
    pub(super) fn has_tcp(&self) -> bool {
        self.tcp.is_some()
    }

    #[cfg(test)]
    pub(super) fn has_udp(&self) -> bool {
        self.udp.is_some()
    }

    #[cfg(test)]
    pub(super) fn tcp_local_addr(&self) -> Option<SocketAddr> {
        self.tcp
            .as_ref()
            .and_then(|listener| listener.local_addr().ok())
    }

    #[cfg(test)]
    pub(super) fn udp_local_addr(&self) -> Option<SocketAddr> {
        self.udp
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
    }
}

/// Process-scoped supervisor ownership retained by `ControlPlane::run`.
pub(super) struct DnsListener {
    phase: watch::Sender<ListenerPhase>,
    supervisors: JoinSet<anyhow::Result<()>>,
}

impl DnsListener {
    /// Close receive/accept admission while allowing already tracked children
    /// to finish as part of the control plane's ordinary bounded drain.
    pub(super) fn stop_accepting(&self) {
        let _ = self.phase.send(ListenerPhase::StopAccepting);
    }

    /// Force-cancel any child that outlived the bounded drain and join every
    /// supervisor. Each supervisor owns and drains its own child `JoinSet`, so
    /// this leaves no detached query or connection task.
    pub(super) async fn abort_and_join(&mut self) -> anyhow::Result<()> {
        let _ = self.phase.send(ListenerPhase::Abort);
        let mut failure = None;
        while let Some(result) = self.supervisors.join_next().await {
            if let Err(error) = result
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for DnsListener {
    fn drop(&mut self) {
        let _ = self.phase.send(ListenerPhase::Abort);
        self.supervisors.abort_all();
    }
}

fn resolve_bind_addresses(endpoint: &DnsBindEndpoint) -> io::Result<Vec<SocketAddr>> {
    if endpoint.host().is_empty() {
        // Go's wildcard listeners prefer a dual-stack IPv6 socket and fall
        // back to IPv4 when IPv6 is unavailable. Try the same two concrete
        // addresses while still publishing at most one listener per transport.
        return Ok(vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), endpoint.port()),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), endpoint.port()),
        ]);
    }

    let mut addresses: Vec<_> = (endpoint.host(), endpoint.port())
        .to_socket_addrs()?
        .collect();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "dns.bind hostname resolved to no address",
        ));
    }
    Ok(addresses)
}

fn bind_tcp_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    // SO_REUSEADDR permits an immediate process restart across accepted
    // connections in TIME_WAIT; without SO_REUSEPORT it cannot share a live
    // listener tuple.
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn bind_udp_listener(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    let _ = socket.set_recv_buffer_size(4 << 20);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let socket = std::net::UdpSocket::from(socket);
    enable_bound_udp_packet_info(&socket, addr.is_ipv6())?;
    Ok(socket)
}

fn bind_selected(
    addr: SocketAddr,
    tcp_enabled: bool,
    udp_enabled: bool,
) -> io::Result<BoundDnsListener> {
    debug_assert!(tcp_enabled || udp_enabled);

    // UDP reserves the port first in dual ephemeral mode, then TCP takes the
    // selected port. A cross-protocol collision drops both sockets and the
    // caller retries with another kernel-selected port.
    let udp = if udp_enabled {
        let socket = bind_udp_listener(addr)?;
        Some(socket)
    } else {
        None
    };

    let selected_addr = match &udp {
        Some(socket) if addr.port() == 0 => socket.local_addr()?,
        _ => addr,
    };
    let tcp = if tcp_enabled {
        let listener = bind_tcp_listener(selected_addr)?;
        Some(listener)
    } else {
        None
    };
    #[cfg(test)]
    let local_addr = match (&udp, &tcp) {
        (Some(socket), _) => socket.local_addr()?,
        (None, Some(listener)) => listener.local_addr()?,
        (None, None) => unreachable!("validated dns.bind selects a transport"),
    };

    Ok(BoundDnsListener {
        tcp,
        udp,
        #[cfg(test)]
        local_addr,
    })
}

async fn run_udp_supervisor(
    socket: Arc<UdpSocket>,
    controller: Arc<DnsController>,
    stats: Arc<StatsManager>,
    drain: Arc<DrainTracker>,
    mut phase: watch::Receiver<ListenerPhase>,
    native: Option<Arc<crate::observe::Observation>>,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
) -> anyhow::Result<()> {
    let mut batch = super::sockets::UdpRecvBatch::new()?;
    let mut children = JoinSet::new();
    let mut failure = None;
    let local_addr = match socket.local_addr() {
        Ok(local_addr) => local_addr,
        Err(error) => {
            error!(error_kind = ?error.kind(), "standalone UDP DNS receive failed");
            return Err(error.into());
        }
    };
    // A persistent receive error repeats every iteration; warn once per episode.
    let mut receive_failing = false;

    'receive: loop {
        tokio::select! {
            biased;
            changed = phase.changed() => {
                if changed.is_err() || *phase.borrow() != ListenerPhase::Running {
                    break;
                }
            }
            completed = children.join_next(), if !children.is_empty() => {
                retain_child_result(&mut failure, completed, false, "UDP query");
            }
            received = super::sockets::recv_batch_from_with_orig_dst(socket.as_ref(), local_addr, &mut batch) => {
                if let Err(error) = received {
                    crate::logging::warn_on_entry!(
                        !std::mem::replace(&mut receive_failing, true),
                        error_kind = ?error.kind(),
                        "standalone UDP DNS receive failed"
                    );
                    continue;
                }
                let received = batch.len();
                for index in 0..received {
                    let (query, client_addr, meta) = match batch.packet(index) {
                        Ok(packet) => packet,
                        Err(error) => {
                            crate::logging::warn_on_entry!(
                                !std::mem::replace(&mut receive_failing, true),
                                error_kind = ?error.kind(),
                                "standalone UDP DNS receive failed"
                            );
                            continue;
                        }
                    };
                    if std::mem::replace(&mut receive_failing, false) {
                        info!("standalone UDP DNS receive recovered");
                    }
                    if !tokio::task::coop::has_budget_remaining() {
                        tokio::task::yield_now().await;
                    }
                    if *phase.borrow() != ListenerPhase::Running {
                        break 'receive;
                    }
                    let Some(response_source) = udp_response_source(&meta) else {
                        debug!(%client_addr, "standalone UDP DNS datagram has no reply source address");
                        continue;
                    };
                    #[cfg(feature = "native-api")]
                    let started = std::time::Instant::now();
                    let observation = crate::control::connection::observation::ConnectionObservation::begin(
                        native.as_deref(), crate::observe::vocab::Network::Udp, client_addr, SocketAddr::new(response_source.0, local_addr.port()),
                    );
                    let observer = observation.observer(|| diagnostics.read().generation, "client_dns");

                    if drain.should_reject() {
                        let refused = minimal_dns_error_response(query, 5);
                        let operation = async { Ok(send_udp_refused(socket.as_ref(), &refused, response_source, client_addr).await) };
                        #[cfg(feature = "native-api")]
                        let operation = observe_bound_error(&observation, observer, query, client_addr, "draining", operation);
                        #[cfg(not(feature = "native-api"))]
                        let operation = async { operation.await.map_err(|_: crate::dns::runtime::RuntimeCancelled| ()) };
                        let _ = operation.await;
                        #[cfg(feature = "native-api")]
                        controller.dns_service().observer.observe_client(query, crate::dns::query::IngressProfile::Udp { advertised_size: 512 }, Some(client_addr), None, &refused, started.elapsed());
                        continue;
                    }

                    let admission = match controller.try_admit_query(true) {
                        Ok(admission) => {
                            stats.record_udp_slow_permit_accepted();
                            admission
                        }
                        Err(error) => {
                            if error.udp_reply.is_some() {
                                stats.record_udp_slow_permit_accepted();
                            } else {
                                stats.record_udp_slow_permit_rejected();
                            }
                            let refused = minimal_dns_error_response(query, 5);
                            let operation = error.run_reply(send_udp_refused(socket.as_ref(), &refused, response_source, client_addr));
                            #[cfg(feature = "native-api")]
                            let operation = observe_bound_error(&observation, observer, query, client_addr, "admission_refused", operation);
                            let _ = operation.await;
                            #[cfg(feature = "native-api")]
                            controller.dns_service().observer.observe_client(query, crate::dns::query::IngressProfile::Udp { advertised_size: 512 }, Some(client_addr), None, &refused, started.elapsed());
                            continue;
                        }
                    };
                    let Some(validated) = validate_exact_dns_query(query) else {
                        let response = minimal_dns_error_response(query, 1);
                        let operation = admission.run_reply(send_bound_udp_response(
                            socket.as_ref(), &response, response_source, client_addr,
                        ));
                        #[cfg(feature = "native-api")]
                        let operation = observe_bound_error(&observation, observer, query, client_addr, "invalid_query", operation);
                        if let Ok(Err(error)) = operation.await {
                            debug!(error_kind = ?error.kind(), %client_addr, "standalone UDP DNS FORMERR send failed");
                        }
                        #[cfg(feature = "native-api")]
                        controller.dns_service().observer.observe_client(query, crate::dns::query::IngressProfile::Udp { advertised_size: 512 }, Some(client_addr), None, &response, started.elapsed());
                        continue;
                    };
                    // All bounded admission is owned before the datagram copy and
                    // child allocation. Register the drain guard before spawn so a
                    // simultaneous shutdown cannot observe an untracked query.
                    let ingress = validated.ingress();
                    let query = query.to_vec();
                    let guard = ConnectionGuard::new(Arc::clone(&drain));
                    let child_socket = Arc::clone(&socket);
                    let child_controller = Arc::clone(&controller);
                    let child = Box::pin(async move {
                        let _guard = guard;
                        let metadata = DnsRequestMeta::new(Some(client_addr.ip()), None);
                        let operation = async {
                        let response = child_controller
                            .answer_query(&admission, &query, metadata, ingress)
                            .await;
                        match admission
                            .run_reply(send_bound_udp_response(
                                child_socket.as_ref(),
                                response.wire(),
                                response_source,
                                client_addr,
                            ))
                            .await
                        {
                            Ok(Err(error)) => {
                                crate::observe::flows::dns::delivery("delivery_failed", Some("client_send_failed"));
                                debug!(error_kind = ?error.kind(), %client_addr, "standalone UDP DNS response send failed");
                            }
                            Err(_) => {
                                crate::observe::flows::dns::delivery("cancelled", Some("runtime_retired"));
                                debug!(%client_addr, "standalone UDP DNS response cancelled with runtime retirement");
                            }
                            Ok(Ok(_)) => {
                                crate::observe::flows::dns::delivery("delivered", None);
                            }
                        }
                        #[cfg(feature = "native-api")]
                        child_controller.dns_service().observer.observe_client(&query, ingress, Some(client_addr), response.outcome(), response.wire(), started.elapsed());
                        };
                        crate::observe::scope_pin!(operation);
                        let operation = crate::observe::flows::dns::client_scope(&query, ingress, metadata, operation);
                        match observer {
                            Some(observer) => observer.scope(operation).await,
                            None => operation.await,
                        }
                        observation.finish(crate::observe::vocab::ConnectionState::Closed, "dns_query_completed");
                    });
                    start_query(&mut children, &phase, &mut failure, child).await;
                }
                for _ in 0..received {
                    let Some(completed) = children.try_join_next() else {
                        break;
                    };
                    retain_child_result(&mut failure, Some(completed), false, "UDP query");
                }
            }
        }
    }

    drop(socket);
    finish_children(&mut children, &mut phase, &mut failure, "UDP query").await;
    failure.map_or(Ok(()), Err)
}

/// Polls a query once on the supervisor so ready answers skip a task spawn;
/// only unfinished work becomes a joined child. A panic fails teardown like a
/// child join error, and Abort drops unfinished work as `abort_all` would.
async fn start_query<F>(
    children: &mut JoinSet<()>,
    phase: &watch::Receiver<ListenerPhase>,
    failure: &mut Option<anyhow::Error>,
    mut child: std::pin::Pin<Box<F>>,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let polled = poll_fn(|cx| {
        Poll::Ready(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || child.as_mut().poll(cx),
        )))
    })
    .await;
    match polled {
        Ok(Poll::Ready(())) => {}
        Ok(Poll::Pending) => {
            if *phase.borrow() != ListenerPhase::Abort {
                children.spawn(child);
            }
        }
        Err(_) => {
            debug!(label = "UDP query", "standalone DNS child panicked");
            failure.get_or_insert_with(|| {
                anyhow::anyhow!("standalone DNS child panicked").context("UDP query")
            });
        }
    }
}

async fn send_udp_refused(
    socket: &UdpSocket,
    response: &[u8],
    response_source: (IpAddr, u32),
    client_addr: SocketAddr,
) -> io::Result<usize> {
    let result = send_bound_udp_response(socket, response, response_source, client_addr).await;
    if let Err(error) = &result {
        debug!(error_kind = ?error.kind(), %client_addr, "standalone UDP DNS REFUSED send failed");
    }
    result
}

#[cfg(feature = "native-api")]
async fn observe_bound_error(
    observation: &crate::control::connection::observation::ConnectionObservation,
    observer: Option<honk_outbound::runtime::flow_observation::FlowObserver>,
    query: &[u8],
    client: SocketAddr,
    reason: &'static str,
    operation: impl Future<Output = Result<io::Result<usize>, crate::dns::runtime::RuntimeCancelled>>,
) -> Result<io::Result<usize>, crate::dns::runtime::RuntimeCancelled> {
    let operation = async {
        crate::observe::flows::dns::decision("rejected", Some(reason));
        let result = operation.await;
        crate::observe::flows::dns::reply_delivery(
            &result,
            |length| *length == 12,
            "client_send_failed",
        );
        result
    };
    let operation = std::pin::pin!(operation);
    let operation = crate::observe::flows::dns::client_scope(
        query,
        crate::dns::query::IngressProfile::Udp {
            advertised_size: 512,
        },
        DnsRequestMeta::new(Some(client.ip()), None),
        operation,
    );
    let result = match observer {
        Some(observer) => observer.scope(operation).await,
        None => operation.await,
    };
    observation.finish(
        crate::observe::vocab::ConnectionState::Closed,
        "dns_error_reply_completed",
    );
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp_supervisor(
    listener: TcpListener,
    controller: Arc<DnsController>,
    connection_limit: Arc<Semaphore>,
    standalone_tcp_limit: Arc<Semaphore>,
    drain: Arc<DrainTracker>,
    mut phase: watch::Receiver<ListenerPhase>,
    #[cfg(feature = "native-api")] native: Option<Arc<crate::observe::Observation>>,
    #[cfg(feature = "native-api")] diagnostics: crate::config_diagnostics::SharedDiagnostics,
) -> anyhow::Result<()> {
    let mut children = JoinSet::new();
    let mut failure = None;
    // A persistent accept error repeats every iteration; warn once per episode.
    let mut accept_failing = false;

    loop {
        tokio::select! {
            biased;
            changed = phase.changed() => {
                if changed.is_err() || *phase.borrow() != ListenerPhase::Running {
                    break;
                }
            }
            completed = children.join_next(), if !children.is_empty() => {
                retain_child_result(&mut failure, completed, false, "TCP connection");
            }
            accepted = listener.accept() => {
                let (mut stream, client_addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        crate::logging::warn_on_entry!(
                            !std::mem::replace(&mut accept_failing, true),
                            error_kind = ?error.kind(),
                            "standalone TCP DNS accept failed"
                        );
                        continue;
                    }
                };
                if std::mem::replace(&mut accept_failing, false) {
                    info!("standalone TCP DNS accept recovered");
                }
                if *phase.borrow() != ListenerPhase::Running || drain.should_reject() {
                    continue;
                }
                let standalone_permit = match Arc::clone(&standalone_tcp_limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(%client_addr, "dropping standalone TCP DNS connection at listener capacity");
                        continue;
                    }
                };
                let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(%client_addr, "dropping standalone TCP DNS connection at capacity");
                        continue;
                    }
                };
                let guard = ConnectionGuard::new(Arc::clone(&drain));
                let child_controller = Arc::clone(&controller);
                #[cfg(feature = "native-api")]
                let observation = stream.local_addr().ok().map(|destination| {
                    crate::control::connection::observation::ConnectionObservation::begin(
                        native.as_deref(), crate::observe::vocab::Network::Tcp, client_addr, destination,
                    )
                });
                #[cfg(feature = "native-api")]
                let observer = observation.as_ref().and_then(|observation|
                    observation.observer(|| diagnostics.read().generation, "client_dns"));
                children.spawn(async move {
                    let _permit = permit;
                    let _standalone_permit = standalone_permit;
                    let _guard = guard;
                    let operation = child_controller.serve_bound_tcp_dns(&mut stream, client_addr);
                    #[cfg(feature = "native-api")]
                    let result = match observer {
                        Some(observer) => observer.scope(operation).await,
                        None => operation.await,
                    };
                    #[cfg(not(feature = "native-api"))]
                    let result = operation.await;
                    drop(stream);
                    #[cfg(feature = "native-api")]
                    if let Some(observation) = observation {
                        observation.finish(
                            if result.is_ok() { crate::observe::vocab::ConnectionState::Closed } else { crate::observe::vocab::ConnectionState::Failed },
                            if result.is_ok() { "dns_connection_closed" } else { "dns_connection_failed" },
                        );
                    }
                    if result.is_err() {
                        debug!(error_kind = "connection", %client_addr, "standalone TCP DNS connection failed");
                    }
                });
            }
        }
    }

    drop(listener);
    finish_children(&mut children, &mut phase, &mut failure, "TCP connection").await;
    failure.map_or(Ok(()), Err)
}

async fn finish_children(
    children: &mut JoinSet<()>,
    phase: &mut watch::Receiver<ListenerPhase>,
    failure: &mut Option<anyhow::Error>,
    label: &'static str,
) {
    let mut aborted = *phase.borrow() == ListenerPhase::Abort;
    if aborted {
        children.abort_all();
    }

    while !children.is_empty() {
        tokio::select! {
            changed = phase.changed(), if !aborted => {
                if changed.is_err() || *phase.borrow() == ListenerPhase::Abort {
                    aborted = true;
                    children.abort_all();
                }
            }
            completed = children.join_next() => retain_child_result(failure, completed, aborted, label),
        }
    }
}

fn retain_child_result(
    failure: &mut Option<anyhow::Error>,
    completed: Option<Result<(), tokio::task::JoinError>>,
    aborted: bool,
    label: &'static str,
) {
    if let Some(Err(error)) = completed
        && (!aborted || !error.is_cancelled())
    {
        debug!(label, "standalone DNS child join failed");
        failure.get_or_insert_with(|| anyhow::Error::new(error).context(label));
    }
}

#[cfg(test)]
mod tests;
