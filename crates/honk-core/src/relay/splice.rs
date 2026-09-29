//! Zero-copy bidirectional TCP relay via the `splice(2)` syscall.
//!
//! Moves data directly between two plain TCP sockets through kernel pipes,
//! avoiding userspace copies entirely:
//!
//! ```text
//! client ──splice──→ pipe[1]  pipe[0] ──splice──→ upstream
//! client ◄──splice── pipe[0]  pipe[1] ◄──splice── upstream
//! ```
//!
//! Each direction runs as an independent pump driven by tokio readiness
//! (`TcpStream::async_io`, which re-arms readiness on `WouldBlock`, so the
//! raw syscalls never busy-loop). When one direction sees EOF it shuts down
//! the opposite socket's write side (half-close propagation) and the other
//! direction drains until its own EOF — bounded by [`DRAIN_DEADLINE`] so a
//! silent peer cannot pin the relay forever.
//!
//! The first splice of each direction doubles as a capability probe: a
//! failed `splice(2)` moves no bytes, so if it returns EINVAL/ENOSYS/EXDEV
//! the whole connection falls back to the userspace copy relay without
//! losing data, and a global flag skips probing for future connections.
//!
//! Go ref: `tcp_copy_linux.go` (340L), `tcp_copy_engine.go` (118L)

use super::{RelayStats, is_ignorable_connection_error, relay_tcp};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::Interest;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Upper bound requested for one active splice direction. A live pipe owns
/// two FDs and at most this many kernel-buffer bytes; a full-duplex relay is
/// therefore bounded to four FDs and 128 KiB of requested pipe pages. Linux
/// may refuse the resize, in which case `capacity` records the smaller
/// kernel-selected value.
const PIPE_SIZE: usize = 64 * 1024;

/// Conservative capacity used only when `F_GETPIPE_SZ` itself fails.
const DEFAULT_PIPE_SIZE: usize = 64 * 1024;

/// Set when the kernel rejects `splice(2)` for TCP sockets (e.g. seccomp).
/// Once latched, every connection uses the userspace copy relay directly.
static SPLICE_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

/// Whether `splice(2)` has worked so far on this host.
pub fn splice_available() -> bool {
    !SPLICE_UNSUPPORTED.load(Ordering::Relaxed)
}

/// Whether an errno from the very first `splice(2)` attempt means "splice
/// is not supported for these file descriptors" (as opposed to a regular
/// connection error). Only checked before any byte has been moved, so
/// falling back to the copy relay loses nothing.
fn is_unsupported_errno(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EXDEV) | Some(libc::EPERM)
    )
}

/// Outcome of a failed splice operation.
#[derive(Debug)]
pub(super) enum SpliceError {
    /// `splice(2)` is unavailable for these fds or denied by policy, before
    /// any byte was moved.
    Unsupported,
    /// The pipes could not be created, before any byte was moved; unlike
    /// `Unsupported` this says nothing about later connections.
    NoPipe(io::Error),
    /// A regular I/O error.
    Io(super::RelayError),
}

impl SpliceError {
    fn classify(err: io::Error, client_side: bool) -> Self {
        if is_unsupported_errno(&err) {
            SpliceError::Unsupported
        } else {
            SpliceError::Io(super::RelayError::new(err, client_side))
        }
    }

    /// Verdicts reached before any byte moved leave both streams intact, so
    /// the caller resumes on the copy relay. Only `Unsupported` disables
    /// splice for later connections.
    pub(super) fn into_fallback(self) -> Result<(), super::RelayError> {
        match self {
            SpliceError::Unsupported => {
                SPLICE_UNSUPPORTED.store(true, Ordering::Relaxed);
                debug!("splice(2) unsupported on this host; falling back to copy relay");
            }
            SpliceError::NoPipe(error) => debug!("splice pipes unavailable ({error}); copying"),
            SpliceError::Io(error) => return Err(error),
        }
        Ok(())
    }
}

/// Thin wrapper over `splice(2)` (non-blocking, retries on EINTR).
fn raw_splice(
    fd_in: &impl std::os::fd::AsFd,
    fd_out: &impl std::os::fd::AsFd,
    len: usize,
) -> io::Result<usize> {
    loop {
        match nix::fcntl::splice(
            fd_in,
            None,
            fd_out,
            None,
            len,
            nix::fcntl::SpliceFFlags::SPLICE_F_MOVE | nix::fcntl::SpliceFFlags::SPLICE_F_NONBLOCK,
        ) {
            Ok(moved) => return Ok(moved),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

/// A kernel pipe used as the intermediate buffer for one splice direction.
struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
    capacity: usize,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        #[cfg(test)]
        if test_hook::pipes_fail() {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let (read, write) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_CLOEXEC)
                .map_err(io::Error::from)?;
        // Best-effort: grow the pipe to reduce syscall frequency.
        let _ = nix::fcntl::fcntl(
            &write,
            nix::fcntl::FcntlArg::F_SETPIPE_SZ(PIPE_SIZE as libc::c_int),
        );
        let capacity = nix::fcntl::fcntl(&write, nix::fcntl::FcntlArg::F_GETPIPE_SZ)
            .ok()
            .and_then(|capacity| usize::try_from(capacity).ok())
            .filter(|capacity| *capacity > 0)
            .unwrap_or(DEFAULT_PIPE_SIZE);
        Ok(Pipe {
            read,
            write,
            capacity,
        })
    }
}

/// Half-close the write side of a socket (best-effort).
fn shutdown_write(stream: &TcpStream) {
    let _ = nix::sys::socket::shutdown(stream.as_raw_fd(), nix::sys::socket::Shutdown::Write);
}

/// Perform the very first splice of a direction without waiting for
/// readiness. This doubles as the capability probe: a failed `splice(2)`
/// moves no bytes, so an [`SpliceError::Unsupported`] result here still
/// allows a lossless fallback to the copy relay.
///
/// Returns the number of bytes staged in the pipe (0 when the source had no
/// data ready or is already at EOF; the pump re-reads either way).
fn probe(src: &TcpStream, pipe: &Pipe, client_side: bool) -> Result<usize, SpliceError> {
    #[cfg(test)]
    if let Some(errno) = test_hook::forced_probe_errno(src.as_raw_fd()) {
        return Err(SpliceError::classify(
            io::Error::from_raw_os_error(errno),
            client_side,
        ));
    }
    match raw_splice(src, &pipe.write, pipe.capacity) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
        Err(e) => Err(SpliceError::classify(e, client_side)),
    }
}

/// Splice one direction until the source reaches EOF.
///
/// `staged` is the number of bytes the probe already moved into the pipe.
/// The pump alternates between two states: with an empty pipe it pulls from
/// the source (waiting for readability), with a non-empty pipe it drains to
/// the destination (waiting for writability). EOF is only observed with an
/// empty pipe, so `shutdown(Write)` on the destination propagates a clean
/// half-close after all staged bytes; the reverse direction keeps running.
async fn pump(
    src: &TcpStream,
    dst: &TcpStream,
    pipe: &Pipe,
    mut staged: usize,
    progress: &super::RelayProgress,
    upload: bool,
) -> Result<u64, super::RelayError> {
    let mut total = 0u64;
    let counter = if upload {
        &progress.upload
    } else {
        &progress.download
    };
    let mut first_response = if upload {
        None
    } else {
        progress.first_response.as_ref()
    };

    loop {
        if staged == 0 {
            staged = src
                .async_io(Interest::READABLE, || {
                    raw_splice(src, &pipe.write, pipe.capacity)
                })
                .await
                .map_err(|error| super::RelayError::new(error, upload))?;
            if staged == 0 {
                // Source reached EOF: propagate the half-close.
                shutdown_write(dst);
                return Ok(total);
            }
        } else {
            if let Some(callback) = first_response.take() {
                callback();
            }
            let n = dst
                .async_io(Interest::WRITABLE, || {
                    #[cfg(test)]
                    let staged = test_hook::write_limit(dst.as_raw_fd(), staged)?;
                    let n = raw_splice(&pipe.read, dst, staged)?;
                    #[cfg(test)]
                    test_hook::wrote(dst.as_raw_fd(), n);
                    Ok(n)
                })
                .await
                .map_err(|error| super::RelayError::new(error, !upload))?;
            if n == 0 {
                // A non-empty pipe must always make progress; bail out
                // instead of spinning.
                return Err(super::RelayError::new(
                    io::Error::new(
                        io::ErrorKind::WriteZero,
                        "splice pipe→socket made no progress",
                    ),
                    !upload,
                ));
            }
            staged -= n;
            total += n as u64;
            counter.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(callback) = &progress.on_transfer {
                if upload {
                    callback(n as u64, 0);
                } else {
                    callback(0, n as u64);
                }
            }
        }
    }
}

/// Idle budget for the surviving direction after the first EOF: it is cut
/// only when this much time passes without any byte of progress, so a
/// silent peer cannot pin the relay task and both sockets forever —
/// observed in production as a growing pile of CLOSE-WAIT accepted
/// sockets. Active transfers may outlive it freely.
pub(crate) const DRAIN_DEADLINE: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(500)
} else {
    std::time::Duration::from_secs(30)
};

/// Shared engine behind [`splice_bidirectional`] and [`relay_splice`].
pub(super) async fn run(
    client: &TcpStream,
    upstream: &TcpStream,
    progress: super::OptionalRelayProgress,
) -> Result<(u64, u64), SpliceError> {
    let pipe_c2p = Pipe::new().map_err(SpliceError::NoPipe)?;
    let pipe_p2c = Pipe::new().map_err(SpliceError::NoPipe)?;

    // The probes run before any byte reaches a destination socket, so an
    // `Unsupported` verdict here still allows a lossless copy fallback.
    let staged_c2p = probe(client, &pipe_c2p, true)?;
    let staged_p2c = match probe(upstream, &pipe_p2c, false) {
        Ok(n) => n,
        Err(SpliceError::Unsupported) if staged_c2p == 0 => return Err(SpliceError::Unsupported),
        Err(SpliceError::Unsupported) => {
            // Unreachable in practice (the first probe already succeeded on
            // the same kind of fds), but bytes have left the client socket,
            // so a copy fallback would lose them. Fail instead of silently
            // corrupting the stream.
            return Err(SpliceError::Io(super::RelayError::new(
                io::Error::other("splice probe failed after staging bytes"),
                false,
            )));
        }
        Err(e) => return Err(e),
    };

    // Byte counters double as final stats when the drain deadline cancels
    // the surviving pump before it can return its own total.
    let mut progress = progress.unwrap_or_else(|| super::RelayProgress {
        upload: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        download: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        first_response: None,
        on_transfer: None,
    });
    if staged_p2c > 0
        && let Some(callback) = progress.first_response.take()
    {
        callback();
    }
    let c2p = pump(client, upstream, &pipe_c2p, staged_c2p, &progress, true);
    let p2c = pump(upstream, client, &pipe_p2c, staged_p2c, &progress, false);
    tokio::pin!(c2p);
    tokio::pin!(p2c);

    // The first direction to finish half-closes the other (inside pump);
    // the survivor then drains until its own EOF or a full DRAIN_DEADLINE
    // without progress (a slow active download is never cut). An error in
    // either direction still cancels the whole relay, mirroring
    // `copy_bidirectional`.
    let c2p_first = match tokio::select! {
        r = &mut c2p => r.map(|_| true),
        r = &mut p2c => r.map(|_| false),
    } {
        Ok(b) => b,
        Err(e) => return Err(SpliceError::Io(e)),
    };
    let (survivor, survivor_cnt) = if c2p_first {
        (&mut p2c, &progress.download)
    } else {
        (&mut c2p, &progress.upload)
    };
    match super::drain_wait(survivor, survivor_cnt).await {
        Ok(_) => {}
        Err(e) => return Err(SpliceError::Io(e)),
    }
    Ok((
        progress.upload.load(Ordering::Relaxed),
        progress.download.load(Ordering::Relaxed),
    ))
}

/// Relay two plain TCP sockets with zero-copy `splice(2)`.
///
/// Returns the bytes moved in each direction `(client→upstream,
/// upstream→client)`, matching `tokio::io::copy_bidirectional` accounting.
///
/// Half-close propagation: when one direction reaches EOF, the opposite
/// socket's write side is shut down and the reverse direction drains until
/// its own EOF (bounded by [`DRAIN_DEADLINE`]) before returning. Both
/// sockets are shut down on exit.
///
/// Returns `ErrorKind::Unsupported` when the kernel rejects `splice(2)` on
/// the capability probe (before any byte is moved). Callers that still own
/// equivalent streams may then retry with the copy relay; [`relay_splice`]
/// handles that fallback itself.
pub async fn splice_bidirectional(
    client: TcpStream,
    upstream: TcpStream,
) -> io::Result<(u64, u64)> {
    let result = run(&client, &upstream, None).await;
    // Shut down both sides regardless of outcome (mirrors `relay_tcp`).
    shutdown_write(&client);
    shutdown_write(&upstream);
    match result {
        Ok(counts) => Ok(counts),
        Err(SpliceError::Unsupported) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "splice(2) not supported for these sockets",
        )),
        Err(SpliceError::NoPipe(error)) => Err(error),
        Err(SpliceError::Io(e)) => Err(e.error),
    }
}

/// Relay two plain TCP sockets, using zero-copy `splice(2)` when the kernel
/// supports it and falling back to the userspace copy relay otherwise.
///
/// Produces the exact same [`RelayStats`] accounting as [`relay_tcp`]; the
/// fallback is lossless because the capability probe runs before any byte
/// is moved, and it is latched process-wide so later connections go
/// straight to the copy path.
pub async fn relay_splice(
    client: &mut TcpStream,
    upstream: TcpStream,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    progress: super::OptionalRelayProgress,
) -> anyhow::Result<RelayStats> {
    if !splice_available() {
        return relay_auto(client, upstream, client_addr, target_addr, progress).await;
    }

    let start = tokio::time::Instant::now();

    debug!(
        "TCP splice relay started: {} → {}",
        client_addr, target_addr
    );

    match run(client, &upstream, progress.clone()).await {
        Ok((c2p_bytes, p2c_bytes)) => {
            shutdown_write(client);
            shutdown_write(&upstream);
            let duration_ms = start.elapsed().as_millis() as u64;
            let stats = RelayStats {
                client_to_proxy: c2p_bytes,
                proxy_to_client: p2c_bytes,
                total_bytes: c2p_bytes + p2c_bytes,
                duration_ms,
            };
            debug!(
                "TCP splice relay complete: {} → {} ({} bytes in {}ms)",
                client_addr, target_addr, stats.total_bytes, duration_ms
            );
            Ok(stats)
        }
        Err(error) => match error.into_fallback() {
            Ok(()) => relay_auto(client, upstream, client_addr, target_addr, progress).await,
            Err(e) => {
                shutdown_write(client);
                shutdown_write(&upstream);
                if !is_ignorable_connection_error(&e.error) {
                    warn!(
                        "TCP splice relay error for {} → {}: {}",
                        client_addr, target_addr, e.error
                    );
                }
                Err(e.into_anyhow())
            }
        },
    }
}

/// Relay entry for proxy streams that are not plain TCP sockets (TLS- or
/// protocol-wrapped). Always uses the userspace copy relay; plain-TCP
/// direct connections go through [`relay_splice`] instead.
///
/// Both sides are generic over async I/O so the proxy side may be a plain TCP
/// socket or a TLS-wrapped stream. When `progress` is provided, byte totals
/// are updated live through the shared counters.
pub async fn relay_auto<S1, S2>(
    client: S1,
    proxy: S2,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    progress: super::OptionalRelayProgress,
) -> anyhow::Result<RelayStats>
where
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    match progress {
        Some(progress) => {
            let (client, proxy) = super::relay_io_pair(client, proxy, &progress);
            relay_tcp(client, proxy, client_addr, target_addr).await
        }
        None => relay_tcp(client, proxy, client_addr, target_addr).await,
    }
}

/// Deterministic capability and partial-write failures around real splice I/O.
#[cfg(test)]
pub(super) mod test_hook {
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, AtomicUsize, Ordering};

    /// The hooks are process-global, so every test driving `run()` holds
    /// this lock.
    pub static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Resets global splice state even when a test panics.
    pub struct StateGuard;

    impl StateGuard {
        pub fn new() -> Self {
            reset();
            StateGuard
        }
    }

    impl Drop for StateGuard {
        fn drop(&mut self) {
            reset();
        }
    }

    /// When non-zero, `probe()` fails with this errno instead of splicing.
    static FORCED_PROBE_ERRNO: AtomicI32 = AtomicI32::new(0);
    static FORCED_PROBE_FD: AtomicI32 = AtomicI32::new(-1);
    /// Number of `probe()` calls, to assert the probe is skipped once the
    /// global "unsupported" flag is latched.
    static PROBE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static WRITE_REMAINING: AtomicIsize = AtomicIsize::new(-1);
    static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
    static PIPES_FAIL: AtomicBool = AtomicBool::new(false);

    pub fn fail_pipes() {
        PIPES_FAIL.store(true, Ordering::Relaxed);
    }

    pub fn pipes_fail() -> bool {
        PIPES_FAIL.load(Ordering::Relaxed)
    }

    pub fn fail_write_after(fd: i32, bytes: isize) {
        WRITE_REMAINING.store(bytes, Ordering::Relaxed);
        WRITE_FD.store(fd, Ordering::Relaxed);
    }

    pub fn write_limit(fd: i32, requested: usize) -> std::io::Result<usize> {
        if WRITE_FD.load(Ordering::Relaxed) != fd {
            return Ok(requested);
        }
        match WRITE_REMAINING.load(Ordering::Relaxed) {
            -1 => Ok(requested),
            0 => Err(std::io::Error::from_raw_os_error(libc::EPIPE)),
            remaining => Ok(requested.min(remaining as usize).min(3)),
        }
    }

    pub fn wrote(fd: i32, bytes: usize) {
        if WRITE_FD.load(Ordering::Relaxed) == fd {
            WRITE_REMAINING.fetch_sub(bytes as isize, Ordering::Relaxed);
        }
    }

    pub fn forced_probe_errno(fd: i32) -> Option<i32> {
        PROBE_CALLS.fetch_add(1, Ordering::Relaxed);
        let target = FORCED_PROBE_FD.load(Ordering::Relaxed);
        if target != -1 && target != fd {
            return None;
        }
        match FORCED_PROBE_ERRNO.load(Ordering::Relaxed) {
            0 => None,
            e => Some(e),
        }
    }

    pub fn probe_calls() -> usize {
        PROBE_CALLS.load(Ordering::Relaxed)
    }

    pub fn set_forced_errno(errno: i32, fd: i32) {
        FORCED_PROBE_ERRNO.store(errno, Ordering::Relaxed);
        FORCED_PROBE_FD.store(fd, Ordering::Relaxed);
    }

    pub fn reset() {
        FORCED_PROBE_ERRNO.store(0, Ordering::Relaxed);
        FORCED_PROBE_FD.store(-1, Ordering::Relaxed);
        PROBE_CALLS.store(0, Ordering::Relaxed);
        WRITE_REMAINING.store(-1, Ordering::Relaxed);
        WRITE_FD.store(-1, Ordering::Relaxed);
        PIPES_FAIL.store(false, Ordering::Relaxed);
        super::SPLICE_UNSUPPORTED.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
