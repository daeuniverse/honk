//! Process-scoped standalone DNS listener for `dns.bind`.
//!
//! These sockets are ordinary host-netns listeners. They deliberately do not
//! carry proxy marks and never enter `daens`; only the transparent port-53
//! listeners use that machinery.

use super::{ConnectionGuard, try_admit_udp_slow_path};
use crate::control::dns_control::DnsController;
use crate::control::drain::DrainTracker;
use crate::dns::query::{DnsRequestMeta, validate_exact_dns_query};
use crate::stats::StatsManager;
use honk_config::dns::DnsBindEndpoint;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, warn};

const MAX_UDP_DNS_MESSAGE: usize = u16::MAX as usize;
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
        dns_slow_limit: Arc<Semaphore>,
        connection_limit: Arc<Semaphore>,
        stats: Arc<StatsManager>,
        drain: Arc<DrainTracker>,
    ) -> io::Result<DnsListener> {
        let Self {
            tcp,
            udp,
            local_addr,
        } = self;
        let udp = udp.map(UdpSocket::from_std).transpose()?.map(Arc::new);
        let tcp = tcp.map(TcpListener::from_std).transpose()?;
        let (phase, phase_rx) = watch::channel(ListenerPhase::Running);
        let standalone_tcp_limit = Arc::new(Semaphore::new(standalone_tcp_capacity(
            connection_limit
                .available_permits()
                .saturating_sub(super::TCP_ACCEPT_RESERVE),
        )));
        let mut supervisors = JoinSet::new();

        if let Some(socket) = udp {
            supervisors.spawn(run_udp_supervisor(
                socket,
                Arc::clone(&controller),
                dns_slow_limit,
                stats,
                Arc::clone(&drain),
                phase_rx.clone(),
            ));
        }
        if let Some(listener) = tcp {
            supervisors.spawn(run_tcp_supervisor(
                listener,
                controller,
                connection_limit,
                standalone_tcp_limit,
                drain,
                phase_rx,
            ));
        }

        Ok(DnsListener {
            phase,
            supervisors,
            local_addr,
        })
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
    supervisors: JoinSet<()>,
    local_addr: SocketAddr,
}

impl DnsListener {
    pub(super) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close receive/accept admission while allowing already tracked children
    /// to finish as part of the control plane's ordinary bounded drain.
    pub(super) fn stop_accepting(&self) {
        let _ = self.phase.send(ListenerPhase::StopAccepting);
    }

    /// Force-cancel any child that outlived the bounded drain and join every
    /// supervisor. Each supervisor owns and drains its own child `JoinSet`, so
    /// this leaves no detached query or connection task.
    pub(super) async fn abort_and_join(&mut self) {
        let _ = self.phase.send(ListenerPhase::Abort);
        while let Some(result) = self.supervisors.join_next().await {
            if result.is_err() {
                debug!("standalone DNS supervisor join failed");
            }
        }
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
    let local_addr = match (&udp, &tcp) {
        (Some(socket), _) => socket.local_addr()?,
        (None, Some(listener)) => listener.local_addr()?,
        (None, None) => unreachable!("validated dns.bind selects a transport"),
    };

    Ok(BoundDnsListener {
        tcp,
        udp,
        local_addr,
    })
}

async fn run_udp_supervisor(
    socket: Arc<UdpSocket>,
    controller: Arc<DnsController>,
    dns_slow_limit: Arc<Semaphore>,
    stats: Arc<StatsManager>,
    drain: Arc<DrainTracker>,
    mut phase: watch::Receiver<ListenerPhase>,
) {
    let mut buffer = [0u8; MAX_UDP_DNS_MESSAGE];
    let mut children = JoinSet::new();
    let local_addr = match socket.local_addr() {
        Ok(local_addr) => local_addr,
        Err(error) => {
            warn!(error_kind = ?error.kind(), "standalone UDP DNS receive failed");
            return;
        }
    };

    loop {
        tokio::select! {
            biased;
            changed = phase.changed() => {
                if changed.is_err() || *phase.borrow() != ListenerPhase::Running {
                    break;
                }
            }
            completed = children.join_next(), if !children.is_empty() => {
                log_child_result(completed, "UDP query");
            }
            received = super::sockets::recv_from_with_orig_dst(socket.as_ref(), local_addr, &mut buffer) => {
                let (length, client_addr, meta) = match received {
                    Ok(received) => received,
                    Err(error) => {
                        warn!(error_kind = ?error.kind(), "standalone UDP DNS receive failed");
                        continue;
                    }
                };
                if *phase.borrow() != ListenerPhase::Running {
                    break;
                }
                let Some(response_source) = udp_response_source(&meta) else {
                    warn!(%client_addr, "standalone UDP DNS datagram has no reply source address");
                    continue;
                };
                let query = &buffer[..length];

                if drain.should_reject() {
                    send_udp_refused(socket.as_ref(), query, response_source, client_addr).await;
                    continue;
                }


                let slow_permit = match try_admit_udp_slow_path(&stats, &dns_slow_limit) {
                    Some(permit) => permit,
                    None => {
                        send_udp_refused(socket.as_ref(), query, response_source, client_addr).await;
                        continue;
                    }
                };
                let query_permit = match controller.try_acquire_query() {
                    Ok(permit) => permit,
                    Err(_) => {
                        send_udp_refused(socket.as_ref(), query, response_source, client_addr).await;
                        drop(slow_permit);
                        continue;
                    }
                };
                let Some(validated) = validate_exact_dns_query(query) else {
                    let response = minimal_dns_error_response(query, 1);
                    if let Err(error) = send_bound_udp_response(socket.as_ref(), &response, response_source, client_addr).await {
                        debug!(error_kind = ?error.kind(), %client_addr, "standalone UDP DNS FORMERR send failed");
                    }
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
                children.spawn(async move {
                    let _slow_permit = slow_permit;
                    let _query_permit = query_permit;
                    let _guard = guard;
                    let metadata = DnsRequestMeta::new(Some(client_addr.ip()), None);
                    let response = child_controller.answer_query(&query, metadata, ingress).await;
                    if let Err(error) = send_bound_udp_response(child_socket.as_ref(), &response, response_source, client_addr).await {
                        debug!(error_kind = ?error.kind(), %client_addr, "standalone UDP DNS response send failed");
                    }
                });
            }
        }
    }

    drop(socket);
    finish_children(&mut children, &mut phase, "UDP query").await;
}

async fn send_udp_refused(
    socket: &UdpSocket,
    query: &[u8],
    response_source: (IpAddr, u32),
    client_addr: SocketAddr,
) {
    let response = minimal_dns_error_response(query, 5);
    if let Err(error) =
        send_bound_udp_response(socket, &response, response_source, client_addr).await
    {
        debug!(error_kind = ?error.kind(), %client_addr, "standalone UDP DNS REFUSED send failed");
    }
}

async fn run_tcp_supervisor(
    listener: TcpListener,
    controller: Arc<DnsController>,
    connection_limit: Arc<Semaphore>,
    standalone_tcp_limit: Arc<Semaphore>,
    drain: Arc<DrainTracker>,
    mut phase: watch::Receiver<ListenerPhase>,
) {
    let mut children = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            changed = phase.changed() => {
                if changed.is_err() || *phase.borrow() != ListenerPhase::Running {
                    break;
                }
            }
            completed = children.join_next(), if !children.is_empty() => {
                log_child_result(completed, "TCP connection");
            }
            accepted = listener.accept() => {
                let (mut stream, client_addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        warn!(error_kind = ?error.kind(), "standalone TCP DNS accept failed");
                        continue;
                    }
                };
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
                children.spawn(async move {
                    let _permit = permit;
                    let _standalone_permit = standalone_permit;
                    let _guard = guard;
                    if child_controller
                        .serve_bound_tcp_dns(&mut stream, client_addr)
                        .await
                        .is_err()
                    {
                        debug!(error_kind = "connection", %client_addr, "standalone TCP DNS connection failed");
                    }
                });
            }
        }
    }

    drop(listener);
    finish_children(&mut children, &mut phase, "TCP connection").await;
}

async fn finish_children(
    children: &mut JoinSet<()>,
    phase: &mut watch::Receiver<ListenerPhase>,
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
            completed = children.join_next() => log_child_result(completed, label),
        }
    }
}

fn log_child_result(completed: Option<Result<(), tokio::task::JoinError>>, label: &'static str) {
    if completed.is_some_and(|result| result.is_err_and(|error| !error.is_cancelled())) {
        debug!(label, "standalone DNS child join failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
    use crate::routing::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpSocket, TcpStream};

    struct FixedAddressUpstream {
        address: [u8; 4],
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for FixedAddressUpstream {
        async fn query(&self, _name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(a_response(raw, self.address))
        }
    }

    struct TestRuntimeTransport;

    #[async_trait::async_trait]
    impl crate::dns::runtime::RuntimeTransport for TestRuntimeTransport {
        async fn close(&self) {}
    }

    fn a_response(query: &[u8], address: [u8; 4]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, address[0], address[1], address[2],
            address[3],
        ]);
        response
    }
    fn forwarder_with_config(
        address: [u8; 4],
        config: &honk_config::dns::DnsConfig,
    ) -> (Arc<DnsForwarder>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let upstream = Arc::new(FixedAddressUpstream {
            address,
            calls: Arc::clone(&calls),
        });
        let router = Arc::new(
            crate::dns::routing::DnsRouter::new_from_dns_config(config).expect("test DNS router"),
        );
        let forwarder = Arc::new(
            DnsForwarder::new(
                upstream,
                Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                    16,
                ))),
                router,
            )
            .with_cache_enabled(false),
        );
        (forwarder, calls)
    }

    fn forwarder(address: [u8; 4]) -> (Arc<DnsForwarder>, Arc<AtomicUsize>) {
        forwarder_with_config(address, &honk_config::dns::DnsConfig::default())
    }
    fn controller_with_config(
        address: [u8; 4],
        config: &honk_config::dns::DnsConfig,
    ) -> (Arc<DnsController>, Arc<AtomicUsize>) {
        let (forwarder, calls) = forwarder_with_config(address, config);
        let controller = Arc::new(DnsController::new(
            forwarder,
            Arc::new(tokio::sync::RwLock::new(Box::new(
                crate::ebpf::mock::MockEbpfBackend::new(),
            ))),
            Arc::new(tokio::sync::RwLock::new(
                Router::new(&[], "direct").expect("test traffic router"),
            )),
        ));
        (controller, calls)
    }

    fn controller(address: [u8; 4]) -> (Arc<DnsController>, Arc<AtomicUsize>) {
        controller_with_config(address, &honk_config::dns::DnsConfig::default())
    }

    fn start_listener(
        bind: &str,
        controller: Arc<DnsController>,
        dns_slow_permits: usize,
    ) -> (DnsListener, SocketAddr, Arc<DrainTracker>) {
        start_listener_with_connection_limit(bind, controller, dns_slow_permits, 16)
    }

    fn start_listener_with_connection_limit(
        bind: &str,
        controller: Arc<DnsController>,
        dns_slow_permits: usize,
        connection_permits: usize,
    ) -> (DnsListener, SocketAddr, Arc<DrainTracker>) {
        let endpoint = DnsBindEndpoint::parse(bind).expect("dns.bind endpoint");
        let bound = BoundDnsListener::bind(&endpoint).expect("bind standalone DNS");
        let address = bound.local_addr();
        let drain = Arc::new(DrainTracker::new().with_drain_timeout(Duration::from_millis(20)));
        let listener = bound
            .spawn(
                controller,
                Arc::new(Semaphore::new(dns_slow_permits)),
                Arc::new(Semaphore::new(connection_permits)),
                Arc::new(StatsManager::new()),
                Arc::clone(&drain),
            )
            .expect("spawn standalone DNS");
        (listener, address, drain)
    }

    async fn stop_listener(listener: &mut DnsListener, drain: &DrainTracker) {
        listener.stop_accepting();
        drain.drain().await.expect("drain standalone DNS");
        listener.abort_and_join().await;
        assert_eq!(
            drain.active_count(),
            0,
            "abort_and_join returned before listener children terminated"
        );
    }

    fn query(domain: &str, txid: u16) -> Vec<u8> {
        let mut query = crate::dns::forwarder::build_dns_query(domain, 1);
        query[..2].copy_from_slice(&txid.to_be_bytes());
        query
    }

    fn multi_query(first: &str, second: &str, txid: u16) -> Vec<u8> {
        let mut wire = query(first, txid);
        let second = query(second, txid);
        wire[4..6].copy_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&second[12..]);
        wire
    }

    async fn udp_exchange(address: SocketAddr, query: &[u8]) -> Vec<u8> {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP client");
        client
            .send_to(query, address)
            .await
            .expect("send UDP query");
        let mut response = [0u8; 512];
        let length = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut response))
            .await
            .expect("UDP response timeout")
            .expect("receive UDP response");
        response[..length].to_vec()
    }

    async fn read_tcp_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        crate::dns::transport::read_length_prefixed_into(
            stream,
            &mut response,
            Some(Duration::from_secs(2)),
        )
        .await
        .expect("read TCP DNS response");
        response
    }

    #[test]
    fn selected_transports_and_dual_port_zero_are_exact() {
        let udp_endpoint = DnsBindEndpoint::parse("udp://127.0.0.1:0").unwrap();
        let udp = BoundDnsListener::bind(&udp_endpoint).unwrap();
        assert!(udp.has_udp());
        assert!(!udp.has_tcp());
        drop(udp);

        let tcp_endpoint = DnsBindEndpoint::parse("tcp://127.0.0.1:0").unwrap();
        let tcp = BoundDnsListener::bind(&tcp_endpoint).unwrap();
        assert!(tcp.has_tcp());
        assert!(!tcp.has_udp());
        drop(tcp);

        let dual_endpoint = DnsBindEndpoint::parse("tcp+udp://127.0.0.1:0").unwrap();
        let dual = BoundDnsListener::bind(&dual_endpoint).unwrap();
        assert!(dual.has_tcp());
        assert!(dual.has_udp());
        assert_eq!(dual.tcp_local_addr(), dual.udp_local_addr());
        assert_ne!(dual.local_addr().port(), 0);
    }

    #[test]
    fn standalone_listener_capacities_and_profiles_are_exact() {
        assert_eq!(standalone_tcp_capacity(0), 0);
        assert_eq!(standalone_tcp_capacity(1), 1);
        assert_eq!(standalone_tcp_capacity(8), 2);

        let mut wire = query("large-response.example", 0x5151);
        wire[10..12].copy_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 41, 0xff, 0xff, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            validate_exact_dns_query(&wire).unwrap().ingress(),
            crate::dns::query::IngressProfile::Udp {
                advertised_size: u16::MAX
            }
        );
        let mut undersized = wire.clone();
        let opt_class = undersized.len() - 8;
        undersized[opt_class..opt_class + 2].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            validate_exact_dns_query(&undersized).unwrap().ingress(),
            crate::dns::query::IngressProfile::Udp { advertised_size: 1 }
        );

        let mut opcode_query = query("opcode.example", 0x5252);
        opcode_query[2..4].copy_from_slice(&0x2900u16.to_be_bytes());
        let opcode_error = minimal_dns_error_response(&opcode_query, 5);
        assert_eq!(
            u16::from_be_bytes([opcode_error[2], opcode_error[3]]) & 0x7800,
            0x2800
        );
    }

    #[test]
    fn dual_bind_failure_releases_first_transport_atomically() {
        let occupied_tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = occupied_tcp.local_addr().unwrap();
        let endpoint = DnsBindEndpoint::parse(&format!("tcp+udp://{address}")).unwrap();

        assert!(BoundDnsListener::bind(&endpoint).is_err());
        let udp = std::net::UdpSocket::bind(address)
            .expect("failed dual bind must release its first UDP socket");
        drop(udp);
    }

    #[test]
    fn wildcard_ipv6_sockets_explicitly_enable_dual_stack() {
        let endpoint = DnsBindEndpoint::parse("tcp+udp://:0").unwrap();
        let bound = BoundDnsListener::bind(&endpoint).unwrap();
        if bound.local_addr().is_ipv6() {
            assert!(
                !socket2::SockRef::from(bound.tcp.as_ref().unwrap())
                    .only_v6()
                    .unwrap()
            );
            assert!(
                !socket2::SockRef::from(bound.udp.as_ref().unwrap())
                    .only_v6()
                    .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn udp_listener_routes_query_and_reports_malformed_and_admission_errors() {
        let (controller, calls) = controller([192, 0, 2, 10]);
        let (mut listener, address, drain) =
            start_listener("udp://127.0.0.1:0", Arc::clone(&controller), 8);

        let valid = query("udp.example", 0x1010);
        let response = udp_exchange(address, &valid).await;
        assert_eq!(&response[..2], &valid[..2]);
        assert!(response.windows(4).any(|window| window == [192, 0, 2, 10]));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let multi = multi_query("first.multi.example", "second.multi.example", 0x1110);
        let response = udp_exchange(address, &multi).await;
        assert_eq!(response[3] & 0x0f, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut malformed = query("malformed.example", 0x2020);
        malformed[4..6].copy_from_slice(&2u16.to_be_bytes());
        let response = udp_exchange(address, &malformed).await;
        assert_eq!(response[3] & 0x0f, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        stop_listener(&mut listener, &drain).await;

        let (mut saturated, saturated_address, saturated_drain) =
            start_listener("udp://127.0.0.1:0", Arc::clone(&controller), 0);
        let refused = udp_exchange(saturated_address, &query("busy.example", 0x3030)).await;
        assert_eq!(refused[3] & 0x0f, 5);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        stop_listener(&mut saturated, &saturated_drain).await;
    }
    #[tokio::test]
    async fn standalone_listeners_route_by_exact_peer_source() {
        let mut config = honk_config::dns::DnsConfig::default();
        config.routing.request.rules = vec![honk_config::dns::DnsRequestRule {
            conditions: vec![honk_config::dns::DnsCond::Sip {
                not: false,
                cidrs: vec!["127.0.0.42/32".into()],
            }],
            action: honk_config::dns::DnsRequestAction::Upstream("default".into()),
        }];
        config.routing.request.fallback = honk_config::dns::DnsRequestAction::Reject;
        let (controller, calls) = controller_with_config([192, 0, 2, 30], &config);
        let (mut listener, address, drain) = start_listener("tcp+udp://127.0.0.1:0", controller, 8);

        let udp_client = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 42), 0))
            .await
            .expect("bind source-routed UDP client");
        udp_client
            .send_to(&query("udp-source.example", 0x4040), address)
            .await
            .expect("send source-routed UDP query");
        let mut udp_response = [0u8; 512];
        let udp_length =
            tokio::time::timeout(Duration::from_secs(2), udp_client.recv(&mut udp_response))
                .await
                .expect("source-routed UDP response timeout")
                .expect("receive source-routed UDP response");
        assert!(
            udp_response[..udp_length]
                .windows(4)
                .any(|window| window == [192, 0, 2, 30])
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let rejected_udp = udp_exchange(address, &query("udp-fallback.example", 0x4041)).await;
        assert_eq!(u16::from_be_bytes([rejected_udp[6], rejected_udp[7]]), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let tcp_socket = TcpSocket::new_v4().expect("create source-routed TCP socket");
        tcp_socket
            .bind(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 42).into(), 0))
            .expect("bind source-routed TCP client");
        let mut tcp_client = tcp_socket
            .connect(address)
            .await
            .expect("connect source-routed TCP client");
        let tcp_query = query("tcp-source.example", 0x4042);
        crate::dns::transport::write_length_prefixed(&mut tcp_client, &tcp_query)
            .await
            .expect("write source-routed TCP query");
        let tcp_response = read_tcp_frame(&mut tcp_client).await;
        assert!(
            tcp_response
                .windows(4)
                .any(|window| window == [192, 0, 2, 30])
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(tcp_client);

        let mut rejected_tcp = TcpStream::connect(address)
            .await
            .expect("connect fallback TCP client");
        let rejected_query = query("tcp-fallback.example", 0x4043);
        crate::dns::transport::write_length_prefixed(&mut rejected_tcp, &rejected_query)
            .await
            .expect("write fallback TCP query");
        let rejected_response = read_tcp_frame(&mut rejected_tcp).await;
        assert_eq!(
            u16::from_be_bytes([rejected_response[6], rejected_response[7]]),
            0
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        stop_listener(&mut listener, &drain).await;
    }

    #[tokio::test]
    async fn wildcard_udp_reply_uses_the_queried_local_address() {
        let (controller, _) = controller([192, 0, 2, 20]);
        let (mut listener, address, drain) = start_listener("udp://0.0.0.0:0", controller, 8);
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP client");
        let destination = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), address.port());
        client
            .send_to(&query("reply-source.example", 0x4141), destination)
            .await
            .expect("send wildcard UDP query");

        let mut response = [0u8; 512];
        let (_, response_source) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                .await
                .expect("wildcard UDP response timeout")
                .expect("receive wildcard UDP response");
        assert_eq!(response_source.ip(), destination.ip());

        stop_listener(&mut listener, &drain).await;
    }

    #[tokio::test]
    async fn tcp_listener_serves_persistent_frames_and_closes_malformed_connections() {
        let (controller, calls) = controller([198, 51, 100, 11]);
        let (mut listener, address, drain) = start_listener("tcp://127.0.0.1:0", controller, 8);
        let mut client = TcpStream::connect(address).await.expect("connect TCP DNS");

        for (domain, txid) in [("first.example", 0x1111), ("second.example", 0x2222)] {
            let query = query(domain, txid);
            crate::dns::transport::write_length_prefixed(&mut client, &query)
                .await
                .expect("write TCP DNS query");
            let response = read_tcp_frame(&mut client).await;
            assert_eq!(&response[..2], &query[..2]);
            assert!(
                response
                    .windows(4)
                    .any(|window| window == [198, 51, 100, 11])
            );
        }

        let multi = multi_query("first.tcp.multi", "second.tcp.multi", 0x3333);
        crate::dns::transport::write_length_prefixed(&mut client, &multi)
            .await
            .expect("write multi-question TCP DNS query");
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
            .await
            .expect("multi-question TCP close timeout")
            .expect("read multi-question TCP close");
        assert_eq!(read, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(client);

        let mut malformed_client = TcpStream::connect(address)
            .await
            .expect("connect malformed TCP DNS");
        crate::dns::transport::write_length_prefixed(&mut malformed_client, &[0u8; 12])
            .await
            .expect("write malformed TCP DNS frame");
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), malformed_client.read(&mut byte))
            .await
            .expect("malformed TCP close timeout")
            .expect("read malformed TCP close");
        assert_eq!(read, 0);

        stop_listener(&mut listener, &drain).await;
    }

    #[tokio::test]
    async fn tcp_listener_preserves_global_connection_capacity() {
        let (controller, _) = controller([203, 0, 113, 20]);
        let (mut listener, address, drain) =
            start_listener_with_connection_limit("tcp://127.0.0.1:0", controller, 8, 4);
        let first = TcpStream::connect(address)
            .await
            .expect("connect first idle TCP DNS client");
        tokio::time::timeout(Duration::from_secs(1), async {
            while drain.active_count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first standalone TCP connection must be tracked");

        let mut second = TcpStream::connect(address)
            .await
            .expect("connect excess TCP DNS client");
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), second.read(&mut byte))
            .await
            .expect("excess TCP DNS close timeout")
            .expect("read excess TCP DNS close");
        assert_eq!(read, 0);
        assert_eq!(drain.active_count(), 1);

        drop(first);
        stop_listener(&mut listener, &drain).await;
    }

    #[tokio::test]
    async fn shutdown_releases_listener_address_for_rebind() {
        let (controller, _) = controller([203, 0, 113, 12]);
        let (mut listener, address, drain) = start_listener("tcp+udp://127.0.0.1:0", controller, 8);
        let mut closed_client = TcpStream::connect(address)
            .await
            .expect("connect malformed TCP DNS client");
        let multi = multi_query("restart.first", "restart.second", 0x5252);
        crate::dns::transport::write_length_prefixed(&mut closed_client, &multi)
            .await
            .expect("write rejected TCP DNS query");
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), closed_client.read(&mut byte))
                .await
                .expect("rejected TCP close timeout")
                .expect("read rejected TCP close"),
            0
        );
        drop(closed_client);
        let _idle_client = TcpStream::connect(address)
            .await
            .expect("connect idle TCP DNS client");
        tokio::time::timeout(Duration::from_secs(1), async {
            while drain.active_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("listener must track the idle TCP connection");
        stop_listener(&mut listener, &drain).await;

        let endpoint = DnsBindEndpoint::parse(&format!("tcp+udp://{address}")).unwrap();
        let rebound = BoundDnsListener::bind(&endpoint)
            .expect("joined listener supervisors must release both sockets");
        assert_eq!(rebound.tcp_local_addr(), Some(address));
        assert_eq!(rebound.udp_local_addr(), Some(address));
    }

    #[tokio::test]
    async fn listener_queries_acquire_the_newly_published_runtime() {
        let (controller, first_calls) = controller([192, 0, 2, 1]);
        let (mut listener, address, drain) =
            start_listener("udp://127.0.0.1:0", Arc::clone(&controller), 8);

        let first = udp_exchange(address, &query("before.example", 0x4141)).await;
        assert!(first.windows(4).any(|window| window == [192, 0, 2, 1]));
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);

        let (replacement_forwarder, replacement_calls) = forwarder([192, 0, 2, 2]);
        let provider = controller.runtime_provider();
        let (generation, projection) = {
            let current = provider.acquire();
            (
                current.runtime().generation().get().saturating_add(1),
                Arc::clone(current.runtime().routing_projection()),
            )
        };
        provider.publish(crate::dns::runtime::DnsRuntime::new(
            crate::dns::runtime::DnsRuntimeParts {
                generation: crate::dns::runtime::RuntimeGeneration::new(generation),
                forwarder: replacement_forwarder,
                routing_projection: projection,
                outbound_runtime: None,
                transport: Arc::new(TestRuntimeTransport),
            },
        ));

        let second = udp_exchange(address, &query("after.example", 0x4242)).await;
        assert!(second.windows(4).any(|window| window == [192, 0, 2, 2]));
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);

        stop_listener(&mut listener, &drain).await;
    }
}
