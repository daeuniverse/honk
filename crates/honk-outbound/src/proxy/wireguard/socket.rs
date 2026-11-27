//! The outer UDP socket: marked, with quinn-udp's GRO receive, `recvmmsg` batching and GSO send.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use tokio::io::Interest;

/// Messages per `recvmmsg`; with GRO each may carry up to 64 datagrams.
pub(super) const RX_MSGS: usize = 8;
/// Kernel UDP GSO limits a send to 64 segments and 65535 payload bytes.
const MAX_GSO_SEGMENTS: usize = 64;
const MAX_GSO_BYTES: usize = 65_000;
/// A stuck socket drops the batch instead of freezing the driver: this is UDP.
const WRITABLE_TIMEOUT: Duration = Duration::from_secs(5);
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct OuterUdp {
    socket: tokio::net::UdpSocket,
    state: UdpSocketState,
    v6: bool,
    drop_log: DropLog,
}

/// Persistent send errors drop every run; log the first and then at most once per interval.
#[derive(Default)]
struct DropLog {
    /// When the last line was logged, and how many drops it has hidden since.
    state: Mutex<(Option<Instant>, u64)>,
}

impl DropLog {
    /// `Some(hidden drops)` when this drop should be logged.
    fn admit(&self, now: Instant) -> Option<u64> {
        let mut state = self.state.lock();
        match state.0 {
            Some(at) if now.duration_since(at) < DROP_LOG_INTERVAL => {
                state.1 += 1;
                None
            }
            _ => {
                state.0 = Some(now);
                Some(std::mem::take(&mut state.1))
            }
        }
    }
}

/// Receive scratch reused for the tunnel's lifetime.
pub(super) struct RxBatch {
    pub(super) bufs: [Vec<u8>; RX_MSGS],
    pub(super) meta: [RecvMeta; RX_MSGS],
}

impl RxBatch {
    pub(super) fn new(socket: &OuterUdp, mtu: u16) -> Self {
        let len = if socket.state.gro_segments() > 1 {
            usize::from(u16::MAX)
        } else {
            (usize::from(mtu) + 64).clamp(2048, usize::from(u16::MAX))
        };
        Self {
            bufs: std::array::from_fn(|_| vec![0; len]),
            meta: [RecvMeta::default(); RX_MSGS],
        }
    }
}

/// Largest receive queue requested, in accounted bytes (the kernel reports and enforces twice
/// that). `SO_RCVBUFFORCE` ignores `rmem_max`, so unauthenticated junk could otherwise pin that
/// much kernel memory per tunnel, and a queue that never drops is a queue that delays: at 5 Gbit/s
/// 128 MiB is ~150 ms of standing latency for every flow. 200 concurrent 16 MiB downloads lost
/// 0–0.6 % of their datagrams at this size (1.4–2.4 % at the 8 MiB the marked socket starts
/// with), against 0 % and 200+ ms at 128 MiB and above.
const RCVBUF_CAP: usize = 64 << 20;

fn force_rcvbuf(socket: &std::net::UdpSocket, request: usize) -> bool {
    let value = libc::c_int::try_from(request).unwrap_or(libc::c_int::MAX);
    // SAFETY: `SO_RCVBUFFORCE` reads one `c_int` from a pointer valid for the call, on a socket
    // this function borrows.
    let result = unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(socket),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            (&raw const value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    result == 0
}

/// Grows the receive queue to hold `request` accounted bytes. One socket carries every flow of the
/// tunnel, so the queue must absorb what all their receive windows put in flight while the owner
/// is busy; every drop is a loss signal to a random flow and a lost SYN costs a second.
/// `SO_RCVBUFFORCE` needs `CAP_NET_ADMIN`; without it the plain option is clamped to `rmem_max`.
/// Returns the effective size.
fn grow_rcvbuf(socket: &std::net::UdpSocket, request: usize) -> usize {
    let sock = socket2::SockRef::from(socket);
    let effective = sock.recv_buffer_size().unwrap_or(0);
    // Never shrinks: a smaller request than the current size is left alone.
    if effective >= request.saturating_mul(2) {
        return effective;
    }
    let forced = force_rcvbuf(socket, request);
    if !forced {
        let _ = sock.set_recv_buffer_size(request);
    }
    let effective = sock.recv_buffer_size().unwrap_or(0);
    tracing::debug!(request, effective, forced, "WireGuard outer receive buffer");
    effective
}

impl OuterUdp {
    /// A dual-stack IPv6 socket when any candidate is IPv6 (IPv4 candidates are sent mapped),
    /// otherwise IPv4; an IPv6 socket that cannot be had falls back to IPv4 candidates.
    /// The receive queue is requested at `rcvbuf` bytes, at most [`RCVBUF_CAP`].
    pub(super) fn bind(candidates: &[SocketAddr], rcvbuf: usize) -> io::Result<Self> {
        let v6_any = SocketAddr::from(([0u16; 8], 0));
        let v4_any = SocketAddr::from(([0, 0, 0, 0], 0));
        let v6_socket = candidates
            .iter()
            .any(SocketAddr::is_ipv6)
            .then(|| crate::util::marked_udp_socket(v6_any))
            .and_then(Result::ok);
        let (std_socket, v6) = match v6_socket {
            Some(socket) => (socket, true),
            None => (crate::util::marked_udp_socket(v4_any)?, false),
        };
        grow_rcvbuf(&std_socket, rcvbuf.min(RCVBUF_CAP));
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        let state = UdpSocketState::new((&socket).into())?;
        Ok(Self {
            socket,
            state,
            v6,
            drop_log: DropLog::default(),
        })
    }

    pub(super) fn is_v6(&self) -> bool {
        self.v6
    }

    pub(super) async fn readable(&self) -> io::Result<()> {
        self.socket.readable().await
    }

    /// Returns the number of filled messages in `batch`.
    pub(super) fn try_recv(&self, batch: &mut RxBatch) -> io::Result<usize> {
        let RxBatch { bufs, meta } = batch;
        let mut slices = bufs.each_mut().map(|buf| IoSliceMut::new(buf));
        self.socket.try_io(Interest::READABLE, || {
            self.state.recv((&self.socket).into(), &mut slices, meta)
        })
    }

    /// Sends back-to-back ciphertexts (`lens` are their sizes), grouping runs of equal size into
    /// GSO sends. Failures drop only the run they hit.
    pub(super) async fn send_all(&self, dst: SocketAddr, buf: &[u8], lens: &[u32]) {
        // A dual-stack socket addresses IPv4 peers by their mapped address.
        let dst = match dst {
            SocketAddr::V4(v4) if self.v6 => {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            dst => dst,
        };
        let gso = self.state.max_gso_segments().min(MAX_GSO_SEGMENTS);
        let (mut off, mut i) = (0, 0);
        while i < lens.len() {
            let seg = lens[i] as usize;
            let (mut bytes, mut j) = (seg, i + 1);
            while gso > 1 && j < lens.len() && j - i < gso {
                let len = lens[j] as usize;
                if len > seg || bytes + len > MAX_GSO_BYTES {
                    break;
                }
                bytes += len;
                j += 1;
                if len < seg {
                    break;
                }
            }
            let transmit = Transmit {
                destination: dst,
                ecn: None,
                contents: &buf[off..off + bytes],
                segment_size: (j - i > 1).then_some(seg),
                src_ip: None,
            };
            if let Err(error) = self.send_one(&transmit).await
                && let Some(suppressed) = self.drop_log.admit(Instant::now())
            {
                tracing::debug!(%error, suppressed, "WireGuard outer send dropped");
            }
            off += bytes;
            i = j;
        }
    }

    async fn send_one(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        loop {
            match self.socket.try_io(Interest::WRITABLE, || {
                self.state.send((&self.socket).into(), transmit)
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::time::timeout(WRITABLE_TIMEOUT, self.socket.writable())
                        .await
                        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
                }
                result => return result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_persistent_send_error_logs_once_per_interval_with_the_hidden_count() {
        let log = DropLog::default();
        let start = Instant::now();
        assert_eq!(log.admit(start), Some(0), "the first drop is logged");
        for step in 1..=1000 {
            assert_eq!(log.admit(start + Duration::from_millis(step)), None);
        }
        let later = start + DROP_LOG_INTERVAL;
        assert_eq!(
            log.admit(later),
            Some(1000),
            "the next line reports what it hid"
        );
        assert_eq!(log.admit(later + Duration::from_secs(1)), None);
    }

    #[tokio::test]
    async fn a_burst_far_beyond_the_marked_sockets_queue_is_kept() {
        const BURST: usize = 20_000;
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        if !force_rcvbuf(&probe, 1 << 20) {
            eprintln!("skipped: SO_RCVBUFFORCE needs CAP_NET_ADMIN");
            return;
        }
        let outer = OuterUdp::bind(&[SocketAddr::from(([127, 0, 0, 1], 1))], 1 << 30).unwrap();
        // The request is capped however large the memory limit is.
        let effective = socket2::SockRef::from(&outer.socket)
            .recv_buffer_size()
            .unwrap();
        assert_eq!(effective, 2 * RCVBUF_CAP);
        let port = outer.socket.local_addr().unwrap().port();
        // Nothing drains while the burst lands, like an owner busy with other work: ~20 MB of
        // datagram accounting, more than the 8 MiB request every marked socket starts with and
        // well inside the cap.
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = [0x5a_u8; 1200];
        for _ in 0..BURST {
            sender.send_to(&payload, ("127.0.0.1", port)).unwrap();
        }
        outer.readable().await.unwrap();
        let mut batch = RxBatch::new(&outer, 1420);
        let mut received = 0;
        loop {
            match outer.try_recv(&mut batch) {
                Ok(n) => {
                    received += batch.meta[..n]
                        .iter()
                        .map(|meta| meta.len.div_ceil(meta.stride.max(1)))
                        .sum::<usize>();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("receive failed: {error}"),
            }
        }
        assert_eq!(
            received, BURST,
            "the kernel dropped datagrams at the outer socket"
        );
    }
}
