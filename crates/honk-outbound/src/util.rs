//! Low-level outbound networking helpers.

use std::io;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpStream;

const EINPROGRESS: i32 = libc::EINPROGRESS;

static BYPASS_MARK: OnceLock<(u32, bool)> = OnceLock::new();

/// Process-wide mark and enforcement policy; initialize before startup network I/O.
pub fn init_dae_socket_mark(mark: u32, required: bool) -> io::Result<()> {
    if mark == 0
        || mark & (honk_ebpf_common::SKB_MARK_RESERVED_MASK | honk_ebpf_common::TPROXY_MARK) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket bypass mark must be nonzero and exclude datapath-reserved and TPROXY bits",
        ));
    }
    if *BYPASS_MARK.get_or_init(|| (mark, required)) != (mark, required) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "socket bypass mark or enforcement policy is already initialized differently",
        ));
    }
    Ok(())
}

/// Effective process mark, retaining the legacy default for standalone users.
pub fn bypass_mark() -> u32 {
    BYPASS_MARK
        .get()
        .map_or(honk_ebpf_common::DAE_BYPASS_MARK, |&(mark, _)| mark)
}

/// Set `SO_MARK`, tolerating permission denial only when the process mark is optional.
#[cfg(target_os = "linux")]
pub fn set_mark_best_effort(socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    set_mark_result_best_effort(socket.set_mark(mark))
}

/// Apply the best-effort `SO_MARK` error contract to an already attempted
/// mark operation. This is also the deterministic injection seam for callers.
#[cfg(target_os = "linux")]
pub fn set_mark_result_best_effort(result: io::Result<()>) -> io::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(e)
            if e.kind() == io::ErrorKind::PermissionDenied
                && !BYPASS_MARK.get().is_some_and(|&(_, required)| required) =>
        {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                tracing::debug!("SO_MARK denied (unprivileged); continuing without bypass mark");
            });
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Set and read back the complete `SO_MARK`; every error or mismatch is fatal.
#[cfg(target_os = "linux")]
pub fn set_mark_verified(socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    socket.set_mark(mark)?;
    let actual = socket.mark()?;
    if actual != mark {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SO_MARK readback mismatch: expected {mark:#x}, received {actual:#x}"),
        ));
    }
    Ok(())
}

/// Bind a nonblocking TCP listener, verifying an optional mark before bind/listen.
pub fn bind_tcp_listener(
    address: SocketAddr,
    egress_mark: Option<u32>,
) -> io::Result<std::net::TcpListener> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    if let Some(mark) = egress_mark {
        set_mark_verified(&socket, mark)?;
    }
    #[cfg(not(target_os = "linux"))]
    if egress_mark.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "required socket marks need Linux",
        ));
    }
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Apply TCP keepalive tuning (idle 15s, interval 10s, 3 probes) via
/// socket2's safe API — no raw setsockopt. The first probe must fire well
/// inside a server's idle-kill window (AnyTLS servers drop idle sessions
/// around 30s): with a 60s first probe, warm mux sessions silently became
/// corpses that only a real flow would discover (mihomo #1891).
#[cfg(target_os = "linux")]
fn apply_tcp_keepalive(socket: &socket2::Socket) -> io::Result<()> {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    socket.set_tcp_keepalive(&keepalive)
}

/// Create a nonblocking TCP socket for `addr`, nodelay + keepalive tuned,
/// optionally `SO_MARK`ed so the eBPF datapath treats it as control-plane
/// traffic and does not re-route it.
fn new_tcp_socket(addr: &SocketAddr, mark: Option<u32>) -> io::Result<socket2::Socket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_keepalive(true)?;
    #[cfg(target_os = "linux")]
    {
        if let Some(mark) = mark {
            set_mark_best_effort(&socket, mark)?;
        }
        apply_tcp_keepalive(&socket)?;
    }
    Ok(socket)
}

/// Create a TCP stream to `addr`, optionally setting `SO_MARK` before the
/// handshake so the local eBPF datapath treats it as control-plane traffic
/// and does not re-route it.
pub async fn connect_marked_addr(
    addr: SocketAddr,
    mark: Option<u32>,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    use crate::runtime::flow_observation::{
        ResolutionLocation, TransportAttempt, TransportError, TransportStatus,
    };
    let mut attempt = TransportAttempt::start(Some(addr), ResolutionLocation::Unknown);
    let result = connect_marked_addr_inner(addr, mark, connect_timeout).await;
    if let Some(attempt) = &mut attempt {
        attempt.finish(
            if result.is_ok() {
                TransportStatus::Succeeded
            } else {
                TransportStatus::Failed
            },
            result.as_ref().err().map(|error| match error.kind() {
                io::ErrorKind::TimedOut => TransportError::Timeout,
                io::ErrorKind::ConnectionRefused => TransportError::ConnectionRefused,
                _ => TransportError::ConnectFailed,
            }),
        );
    }
    result
}

async fn connect_marked_addr_inner(
    addr: SocketAddr,
    mark: Option<u32>,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    let socket = new_tcp_socket(&addr, mark)?;
    match socket.connect(&addr.into()) {
        Ok(()) => {
            let std_stream: std::net::TcpStream = socket.into();
            TcpStream::from_std(std_stream)
        }
        Err(e)
            if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(EINPROGRESS) =>
        {
            let std_stream: std::net::TcpStream = socket.into();
            let stream = TcpStream::from_std(std_stream)?;
            tokio::time::timeout(connect_timeout, stream.writable())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
            if let Some(e) = stream.take_error()? {
                return Err(e);
            }
            Ok(stream)
        }
        Err(e) => Err(e),
    }
}

/// Resolve `addr` (`host:port`) and connect to the first available address
/// with the given optional `SO_MARK`.
pub async fn connect_marked(
    addr: &str,
    mark: Option<u32>,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    // Server hostnames are resolved through the bootstrap resolver when one
    // is configured, so proxy-server DNS does not depend on the regular
    // (potentially self-intercepted) DNS path — see `bootstrap` module docs.
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
    let resolution = crate::bootstrap::resolve(host);
    // Lookup observation enlarges the resolver future embedded by every dial
    // wrapper above this one; inert builds keep their unboxed resolver.
    #[cfg(feature = "flow-observation")]
    let resolution = Box::pin(resolution);
    let (resolution, selection) =
        crate::runtime::flow_observation::observe_resolution(resolution).await;
    let addrs: Vec<_> = resolution?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    // Address fallback stays inside one authoritative node; policy selection
    // and its dial-admission accounting remain unchanged.
    crate::address_race::race_resolved_addrs(&addrs, |addr| {
        let selection = &selection;
        async move {
            if let Some(selection) = selection {
                selection.selected_ip(addr.ip());
            }
            connect_marked_addr(addr, mark, connect_timeout).await
        }
    })
    .await
    .unwrap_or_else(|| {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no address",
        ))
    })
}

/// Connect to the first of the already-resolved `addrs` that accepts, racing
/// them the way [`connect_marked`] does.
pub async fn connect_marked_resolved(
    addrs: &[SocketAddr],
    mark: Option<u32>,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    crate::address_race::race_resolved_addrs(addrs, |addr| {
        connect_marked_addr(addr, mark, connect_timeout)
    })
    .await
    .unwrap_or_else(|| {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no address",
        ))
    })
}

/// Connect to a proxy server from the control plane, bypassing eBPF re-routing.
pub async fn connect_outbound(addr: &str, connect_timeout: Duration) -> io::Result<TcpStream> {
    connect_marked(addr, Some(bypass_mark()), connect_timeout).await
}

/// Bind a UDP socket with `SO_MARK` set so the local eBPF datapath treats it
/// as control-plane traffic and does not re-route it (Go dae `SoMarkFromDae`
/// parity).  Use for every UDP socket the control plane originates — proxy
/// relay sockets, direct UDP, DNS upstream — otherwise `wan_egress` would
/// classify and redirect the packets back into daens, creating a loop.
/// Single bypass-mark implementation shared with `quic::marked_udp_socket`.
pub fn marked_udp_socket(bind_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    marked_udp_socket_with_mark(bind_addr, bypass_mark())
}

pub(crate) fn marked_udp_socket_with_mark(
    bind_addr: SocketAddr,
    mark: u32,
) -> io::Result<std::net::UdpSocket> {
    let domain = if bind_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    set_mark_best_effort(&socket, mark)?;
    // QUIC throughput is buffer-bound: the default 208 KiB rmem caps a
    // ~1ms-RTT path at ~2 Gbps (quic-go sets ~7 MiB and lands dae at ~3
    // Gbps). Request 8 MiB; the kernel clamps to 2×rmem_max, and honk-core
    // raises rmem_max/wmem_max at startup when auto-config is enabled.
    // Best-effort: sockets that don't need it (DNS queries) waste nothing
    // because buffers grow on demand.
    #[cfg(target_os = "linux")]
    {
        const QUIC_SOCK_BUF: usize = 8 << 20;
        let _ = socket.set_recv_buffer_size(QUIC_SOCK_BUF);
        let _ = socket.set_send_buffer_size(QUIC_SOCK_BUF);
    }
    socket.bind(&bind_addr.into())?;
    Ok(socket.into())
}

/// [`marked_udp_socket`] as a tokio socket.
pub async fn udp_marked_bind(bind_addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::from_std(marked_udp_socket(bind_addr)?)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn assert_mark_policy(required: bool) {
        init_dae_socket_mark(0x200, required).unwrap();
        init_dae_socket_mark(0x200, required).unwrap();
        assert_eq!(bypass_mark(), 0x200);
        for (mark, required) in [(0x201, required), (0x200, !required)] {
            assert_eq!(
                init_dae_socket_mark(mark, required).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
        }
        let denied = set_mark_result_best_effort(Err(io::Error::from_raw_os_error(libc::EPERM)));
        if required {
            assert_eq!(denied.unwrap_err().raw_os_error(), Some(libc::EPERM));
        } else {
            denied.unwrap();
        }
        assert_eq!(
            set_mark_result_best_effort(Err(io::Error::from_raw_os_error(libc::EINVAL)))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        set_mark_result_best_effort(Ok(())).unwrap();
    }

    #[test]
    fn required_mark_rejects_permission_denial_and_policy_changes() {
        if crate::bootstrap::run_global_test_in_child(
            "util::tests::required_mark_rejects_permission_denial_and_policy_changes",
        ) {
            return;
        }
        assert_mark_policy(true);
    }

    #[test]
    fn optional_mark_keeps_legacy_permission_denial_contract() {
        if crate::bootstrap::run_global_test_in_child(
            "util::tests::optional_mark_keeps_legacy_permission_denial_contract",
        ) {
            return;
        }
        assert_mark_policy(false);
    }

    #[test]
    fn invalid_process_marks_do_not_claim_initialization() {
        if crate::bootstrap::run_global_test_in_child(
            "util::tests::invalid_process_marks_do_not_claim_initialization",
        ) {
            return;
        }
        for mark in [
            0,
            honk_ebpf_common::CLASSIFIED_MARK | 0x100,
            honk_ebpf_common::NFQUEUE_PENDING_MARK | 0x100,
            honk_ebpf_common::TPROXY_MARK | 0x100,
        ] {
            assert_eq!(
                init_dae_socket_mark(mark, true).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let mark = !(honk_ebpf_common::SKB_MARK_RESERVED_MASK | honk_ebpf_common::TPROXY_MARK);
        init_dae_socket_mark(mark, true).unwrap();
        assert_eq!(bypass_mark(), mark);
    }
}
