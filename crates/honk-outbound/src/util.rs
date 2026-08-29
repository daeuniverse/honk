//! Low-level outbound networking helpers.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

const EINPROGRESS: i32 = libc::EINPROGRESS;

/// Set `SO_MARK` best-effort. In production honk runs as root (eBPF load
/// requires it) so the mark always applies; unprivileged environments (CI,
/// local tests) get EPERM, where we log once and continue unmarked — the
/// bypass is irrelevant there because no eBPF datapath is loaded.
/// Non-EPERM errors are real failures and propagate.
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
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                tracing::debug!("SO_MARK denied (unprivileged); continuing without bypass mark");
            });
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Apply TCP keepalive tuning (idle 60s, interval 10s, 3 probes) via
/// socket2's safe API — no raw setsockopt.
#[cfg(target_os = "linux")]
fn apply_tcp_keepalive(socket: &socket2::Socket) -> io::Result<()> {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
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
    let addrs: Vec<_> = crate::bootstrap::resolve(host)
        .await?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    // Address fallback stays inside one authoritative node; policy selection
    // and its dial-admission accounting remain unchanged.
    crate::address_race::race_resolved_addrs(&addrs, |addr| {
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
    connect_marked(
        addr,
        Some(honk_ebpf_common::DAE_BYPASS_MARK),
        connect_timeout,
    )
    .await
}

/// Bind a UDP socket with `SO_MARK` set so the local eBPF datapath treats it
/// as control-plane traffic and does not re-route it (Go dae `SoMarkFromDae`
/// parity).  Use for every UDP socket the control plane originates — proxy
/// relay sockets, direct UDP, DNS upstream — otherwise `wan_egress` would
/// classify and redirect the packets back into daens, creating a loop.
/// Single bypass-mark implementation shared with `quic::marked_udp_socket`.
pub fn marked_udp_socket(bind_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let domain = if bind_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    set_mark_best_effort(&socket, honk_ebpf_common::DAE_BYPASS_MARK)?;
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
