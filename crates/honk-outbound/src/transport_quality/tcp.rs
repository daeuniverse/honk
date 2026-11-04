use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::{CarrierSample, CarrierSampler, TransportQuality};

/// Lives with the physical I/O owner, never with a logical mux stream.
#[derive(Debug, Default)]
pub(crate) struct TcpPressure {
    sampler: Option<CarrierSampler>,
    last_sample: Option<Instant>,
}

impl TcpPressure {
    pub(crate) fn new(socket: &TcpStream) -> Self {
        let sampler = TransportQuality::current().and_then(|quality| {
            let peer = socket.peer_addr().ok()?;
            Some(CarrierSampler::new(
                quality,
                peer.ip().to_canonical().is_ipv6(),
            ))
        });
        Self {
            sampler,
            last_sample: None,
        }
    }

    pub(crate) fn observe(&mut self, socket: &TcpStream) {
        let Some(sampler) = self.sampler.as_mut() else {
            return;
        };
        if !sampler.quality.is_enabled() {
            sampler.reset();
            return;
        }
        let now = Instant::now();
        if self
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_secs(1))
        {
            return;
        }
        self.last_sample = Some(now);
        sampler.observe(read_sample(socket, now));
    }
}

/// The observer is dormant through TLS/REALITY authentication and has no I/O
/// authority: it neither owns another descriptor nor changes a poll result.
#[derive(Debug)]
pub(crate) struct ObservedTcp {
    inner: TcpStream,
    pressure: TcpPressure,
    active: bool,
}

impl std::os::fd::AsRawFd for ObservedTcp {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.inner)
    }
}

impl ObservedTcp {
    pub(crate) fn new(inner: TcpStream) -> Self {
        let pressure = TcpPressure::new(&inner);
        Self {
            inner,
            pressure,
            active: false,
        }
    }

    pub(crate) fn activate(&mut self) {
        self.active = true;
        self.pressure.observe(&self.inner);
    }

    fn observe(&mut self) {
        if self.active {
            self.pressure.observe(&self.inner);
        }
    }

    /// Lends the socket to a relay that bypasses this wrapper's I/O while
    /// keeping its pressure sampler attached to the same carrier.
    #[cfg(feature = "rprx")]
    pub(crate) fn raw_parts(&mut self) -> (&TcpStream, RawObserver<'_>) {
        let Self {
            inner,
            pressure,
            active,
        } = self;
        (
            inner,
            RawObserver {
                socket: inner,
                pressure,
                active: *active,
            },
        )
    }
}

/// Pressure sampling for I/O performed directly on a lent [`ObservedTcp`] socket.
#[cfg(feature = "rprx")]
pub struct RawObserver<'a> {
    socket: &'a TcpStream,
    pressure: &'a mut TcpPressure,
    active: bool,
}

#[cfg(feature = "rprx")]
impl RawObserver<'_> {
    /// Call after the lent socket made progress; sampling keeps its one-second gate.
    pub fn observe(&mut self) {
        if self.active {
            self.pressure.observe(self.socket);
        }
    }
}

impl AsyncRead for ObservedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.observe();
        }
        result
    }
}

impl AsyncWrite for ObservedTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(&result, Poll::Ready(Ok(n)) if *n > 0) {
            this.observe();
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if matches!(&result, Poll::Ready(Ok(n)) if *n > 0) {
            this.observe();
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn unknown_sample(at: Instant) -> CarrierSample {
    CarrierSample {
        at,
        rtt: None,
        acknowledged: None,
        transmitted: None,
        lost: None,
        lost_bytes: None,
        tx_bytes: None,
        rx_bytes: None,
        tx_datagrams: None,
        rx_datagrams: None,
    }
}

#[cfg(target_os = "linux")]
use libc::tcp_info as TcpInfo;

/// Prefix of the uapi `struct tcp_info`, which bionic's `libc` bindings omit.
/// The kernel copies at most the supplied length and reports it, so fields past
/// this prefix are simply absent; `sample_from_info` checks every offset.
#[cfg(target_os = "android")]
#[repr(C)]
struct TcpInfo {
    tcpi_state: u8,
    tcpi_ca_state: u8,
    tcpi_retransmits: u8,
    tcpi_probes: u8,
    tcpi_backoff: u8,
    tcpi_options: u8,
    tcpi_snd_rcv_wscale: u8,
    tcpi_rate_flags: u8,
    tcpi_rto: u32,
    tcpi_ato: u32,
    tcpi_snd_mss: u32,
    tcpi_rcv_mss: u32,
    tcpi_unacked: u32,
    tcpi_sacked: u32,
    tcpi_lost: u32,
    tcpi_retrans: u32,
    tcpi_fackets: u32,
    tcpi_last_data_sent: u32,
    tcpi_last_ack_sent: u32,
    tcpi_last_data_recv: u32,
    tcpi_last_ack_recv: u32,
    tcpi_pmtu: u32,
    tcpi_rcv_ssthresh: u32,
    tcpi_rtt: u32,
    tcpi_rttvar: u32,
    tcpi_snd_ssthresh: u32,
    tcpi_snd_cwnd: u32,
    tcpi_advmss: u32,
    tcpi_reordering: u32,
    tcpi_rcv_rtt: u32,
    tcpi_rcv_space: u32,
    tcpi_total_retrans: u32,
    tcpi_pacing_rate: u64,
    tcpi_max_pacing_rate: u64,
    tcpi_bytes_acked: u64,
    tcpi_bytes_received: u64,
    tcpi_segs_out: u32,
    tcpi_segs_in: u32,
    tcpi_notsent_bytes: u32,
    tcpi_min_rtt: u32,
    tcpi_data_segs_in: u32,
    tcpi_data_segs_out: u32,
    tcpi_delivery_rate: u64,
    tcpi_busy_time: u64,
    tcpi_rwnd_limited: u64,
    tcpi_sndbuf_limited: u64,
    tcpi_delivered: u32,
    tcpi_delivered_ce: u32,
    tcpi_bytes_sent: u64,
    tcpi_bytes_retrans: u64,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn read_sample(_socket: &TcpStream, at: Instant) -> CarrierSample {
    unknown_sample(at)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_sample(socket: &TcpStream, at: Instant) -> CarrierSample {
    use std::os::fd::{AsFd, AsRawFd};

    // SAFETY: tcp_info is a C integer-only struct with a valid zero value. The
    // borrowed fd cannot outlive this synchronous call or race owner teardown.
    let mut info: TcpInfo = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&info) as libc::socklen_t;
    let fd = socket.as_fd();
    // SAFETY: both writable pointers cover their declared sizes, getsockopt
    // respects the supplied capacity, and no pointer or fd escapes this call.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut TcpInfo).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return unknown_sample(at);
    }
    sample_from_info(&info, length as usize, at)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn sample_from_info(info: &TcpInfo, length: usize, at: Instant) -> CarrierSample {
    macro_rules! field {
        ($field:ident) => {
            (length >= std::mem::offset_of!(TcpInfo, $field) + std::mem::size_of_val(&info.$field))
                .then_some(u64::from(info.$field))
        };
    }
    // Linux TCP_ESTABLISHED is 1; libc does not export the state enum.
    // Closed sockets must not turn the final kernel snapshot into new evidence.
    if field!(tcpi_state) != Some(1) {
        return unknown_sample(at);
    }
    CarrierSample {
        at,
        rtt: field!(tcpi_rtt)
            .filter(|rtt| *rtt > 0)
            .map(Duration::from_micros),
        acknowledged: field!(tcpi_bytes_acked),
        transmitted: field!(tcpi_data_segs_out),
        lost: field!(tcpi_total_retrans),
        lost_bytes: field!(tcpi_bytes_retrans),
        tx_bytes: field!(tcpi_bytes_sent),
        rx_bytes: field!(tcpi_bytes_received),
        tx_datagrams: None,
        rx_datagrams: None,
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests;
