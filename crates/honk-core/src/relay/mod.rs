//! TCP relay engine.
//!
//! Handles bidirectional data relay between a client connection and a
//! proxy connection. Wrapped streams (TLS/protocol) use async I/O with
//! a pair of frame-sized async copy loops; when both ends are plain `TcpStream`s
//! (direct connections), the `splice` module relays them zero-copy via
//! `splice(2)` with automatic fallback to the copy path. An unencrypted Vision
//! carrier starts in the copy loops and may lend its socket to the same
//! splice engine once both directions are Direct (`vision`).
//!
//! ## Architecture
//!
//! ```text
//! Client ◄═══════► honk-core ◄═══════► Proxy Server ◄═══════► Target
//!          (TCP)              (SOCKS5)                  (TCP)
//! ```

pub mod splice;
#[cfg(feature = "rprx")]
mod vision;

#[cfg(test)]
mod progress_tests;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

/// Relay a transparent client connection through a dialed proxy stream.
///
/// A direct dial yields a plain `TcpStream` and relays through `splice(2)`;
/// an unencrypted Vision carrier copies until both directions are Direct and
/// may then splice its socket. Every other wrapped stream uses the copy relay.
/// All paths update the connection's live byte counters as data flows.
pub async fn relay_proxy(
    client: &mut TcpStream,
    proxy: honk_outbound::ProxyStream,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    progress: RelayProgress,
) -> anyhow::Result<RelayStats> {
    let proxy = match proxy.into_tcp_stream() {
        Ok(upstream) => {
            return splice::relay_splice(
                client,
                upstream,
                client_addr,
                target_addr,
                Some(progress),
            )
            .await;
        }
        Err(proxy) => proxy,
    };
    #[cfg(feature = "rprx")]
    let proxy = match proxy.into_vision_splice() {
        Ok(vision) => {
            return vision::relay_vision(client, vision, client_addr, target_addr, progress).await;
        }
        Err(proxy) => proxy,
    };
    splice::relay_auto(
        client,
        proxy.stream,
        client_addr,
        target_addr,
        Some(progress),
    )
    .await
}

/// Check whether a connection error is ignorable (normal connection closure).
///
/// These errors occur during normal network operation and should not be
/// logged at warn level:
/// - `ConnectionReset` — peer sent RST
/// - `BrokenPipe` — writing to a closed connection
/// - `UnexpectedEof` — connection closed cleanly
/// - `TimedOut` — network timeout
/// - `NotConnected` — socket not connected
///
/// Go ref: `daerrors.IsIgnorableConnectionError`
pub fn is_ignorable_connection_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::NotConnected
    )
}

#[derive(Debug, thiserror::Error)]
#[error("client-side relay connection closed")]
pub(crate) struct ClientIoError;

#[derive(Debug)]
struct RelayError {
    error: std::io::Error,
    client: bool,
}

impl RelayError {
    fn new(error: std::io::Error, client_side: bool) -> Self {
        let client = client_side
            && matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::TimedOut
            );
        Self { error, client }
    }

    fn into_anyhow(self) -> anyhow::Error {
        let error = anyhow::Error::new(self.error);
        if self.client {
            error.context(ClientIoError)
        } else {
            error
        }
    }
}

/// Statistics for a relayed connection.
#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    /// Bytes sent from client to proxy
    pub client_to_proxy: u64,
    /// Bytes sent from proxy to client
    pub proxy_to_client: u64,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Live relay counters, source-arrival notification and accepted-write observation.
#[derive(Clone)]
pub struct RelayProgress {
    pub upload: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub download: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub outbound_upload: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    pub outbound_download: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// First nonempty upstream read, independent of client write backpressure.
    pub first_response: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// Accepted destination writes as `(upload_bytes, download_bytes)`.
    pub on_transfer: Option<std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>>,
}

pub type OptionalRelayProgress = Option<RelayProgress>;

/// Preserve read-based tracker/drain accounting while observing accepted writes.
pub(crate) struct RelayIo<S> {
    inner: S,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    aggregate: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    on_progress: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    on_transfer: Option<std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>>,
    write_is_upload: bool,
}

impl<S> RelayIo<S> {
    pub(crate) fn wrap(
        inner: S,
        counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
        aggregate: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
        on_progress: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
        on_transfer: Option<std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>>,
        write_is_upload: bool,
    ) -> Self {
        Self {
            inner,
            counter,
            aggregate,
            on_progress,
            on_transfer,
            write_is_upload,
        }
    }

    fn transferred(&self, n: usize) {
        if n > 0
            && let Some(callback) = &self.on_transfer
        {
            if self.write_is_upload {
                callback(n as u64, 0);
            } else {
                callback(0, n as u64);
            }
        }
    }
}

/// Pairs the relay ends so client reads count as upload and proxy reads as
/// download; only the proxy side reports the first upstream byte.
fn relay_io_pair<S1, S2>(
    client: S1,
    proxy: S2,
    progress: &RelayProgress,
) -> (RelayIo<S1>, RelayIo<S2>) {
    (
        RelayIo::wrap(
            client,
            progress.upload.clone(),
            progress.outbound_upload.clone(),
            None,
            progress.on_transfer.clone(),
            false,
        ),
        RelayIo::wrap(
            proxy,
            progress.download.clone(),
            progress.outbound_download.clone(),
            progress.first_response.clone(),
            progress.on_transfer.clone(),
            true,
        ),
    )
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for RelayIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &poll {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.counter
                    .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                if let Some(aggregate) = &self.aggregate {
                    aggregate.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                }
                if let Some(callback) = self.on_progress.take() {
                    callback();
                }
            }
        }
        poll
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for RelayIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let n = std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_write(cx, data))?;
        self.transferred(n);
        std::task::Poll::Ready(Ok(n))
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let n =
            std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs))?;
        self.transferred(n);
        std::task::Poll::Ready(Ok(n))
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Grace window for the surviving direction after the first EOF, counted
/// as idle time: any byte of progress resets it. See
/// [`splice::DRAIN_DEADLINE`] for why the drain must be bounded.
const DRAIN_DEADLINE: std::time::Duration = splice::DRAIN_DEADLINE;

// A saturated read fits one AnyTLS frame without a one-byte tail.
const RELAY_BUF_SIZE: usize = u16::MAX as usize;
// Idle and chatty flows keep this small buffer; one saturated read marks a
// bulk flow, which uses the full frame size for the rest of its life.
const RELAY_BUF_MIN: usize = 8 * 1024;

/// Stops both copy directions where neither holds unwritten bytes, so the
/// relay can hand the connection to another engine without cancelling a
/// write.
///
/// A direction parks only at its read boundary and only while the other is
/// suspended in a read, which drops nothing. Both copy futures run in one
/// task, so the flags change only between their polls.
struct Park<'a> {
    /// The owner's own condition for handing over, on top of the read boundary.
    gate: &'a (dyn Fn() -> bool + Sync),
    waiting: [AtomicBool; 2],
    taken: AtomicBool,
}

impl Park<'_> {
    fn side(upload: bool) -> usize {
        usize::from(!upload)
    }

    /// Claims the park for the direction at its read boundary.
    fn take(&self, upload: bool) -> bool {
        let claim = !self.taken()
            && self.waiting[Self::side(!upload)].load(Ordering::Relaxed)
            && (self.gate)();
        if claim {
            self.taken.store(true, Ordering::Relaxed);
        }
        claim
    }

    fn set_waiting(&self, upload: bool, waiting: bool) {
        self.waiting[Self::side(upload)].store(waiting, Ordering::Relaxed);
    }

    fn taken(&self) -> bool {
        self.taken.load(Ordering::Relaxed)
    }
}

/// Copy one direction until EOF, then half-close the destination's write
/// side (same contract as `copy_bidirectional`). Bytes read are counted
/// into `progress` so the drain supervisor can tell a stalled survivor
/// from an active one. A taken `park` returns early without closing.
async fn copy_way<R, W>(
    rd: &mut R,
    wr: &mut W,
    progress: std::sync::Arc<std::sync::atomic::AtomicU64>,
    upload: bool,
    park: Option<&Park<'_>>,
) -> Result<u64, RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let read_error = |error| RelayError::new(error, upload);
    let write_error = |error| RelayError::new(error, !upload);
    // Sniffing or protocol setup may already have buffered bytes before the
    // relay starts, independently of bytes read by this copy loop.
    wr.flush().await.map_err(write_error)?;
    let mut rd = RelayIo::wrap(rd, progress, None, None, None, false);
    let mut buffer = vec![0; RELAY_BUF_MIN];
    let mut n = 0;
    loop {
        if park.is_some_and(|park| park.take(upload)) {
            return Ok(n);
        }
        let read = std::future::poll_fn(|cx| {
            use std::pin::Pin;
            use std::task::{Poll, ready};

            let mut chunk = tokio::io::ReadBuf::new(&mut buffer);
            match Pin::new(&mut rd).poll_read(cx, &mut chunk) {
                Poll::Ready(result) => {
                    if let Some(park) = park {
                        park.set_waiting(upload, false);
                    }
                    Poll::Ready(result.map(|()| chunk.filled().len()).map_err(read_error))
                }
                Poll::Pending => {
                    // copy_buf waits here without flushing buffered protocol writes.
                    let flushed = Pin::new(&mut *wr).poll_flush(cx);
                    if let Some(park) = park {
                        park.set_waiting(upload, matches!(flushed, Poll::Ready(Ok(()))));
                    }
                    ready!(flushed).map_err(write_error)?;
                    Poll::Pending
                }
            }
        })
        .await?;
        if read == 0 {
            break;
        }
        wr.write_all(&buffer[..read]).await.map_err(write_error)?;
        n += read as u64;
        if read == buffer.len() && read < RELAY_BUF_SIZE {
            buffer = vec![0; RELAY_BUF_SIZE];
        }
    }
    wr.flush().await.map_err(write_error)?;
    wr.shutdown().await.map_err(write_error)?;
    Ok(n)
}

/// Wait out the surviving direction after its peer finished. The survivor
/// is cut only after a full [`DRAIN_DEADLINE`] without any byte progress —
/// a slow but active download may far exceed the deadline and must not be
/// interrupted. A cut survivor reports the counter's final value, so the
/// bytes it did move are not lost from the stats.
async fn drain_wait(
    f: &mut (impl Future<Output = Result<u64, RelayError>> + Unpin),
    progress: &std::sync::atomic::AtomicU64,
) -> Result<u64, RelayError> {
    const CHECK: std::time::Duration = std::time::Duration::from_millis(100);
    let mut last = 0u64;
    let mut stalled = std::time::Duration::ZERO;
    loop {
        tokio::select! {
            r = &mut *f => return r,
            _ = tokio::time::sleep(CHECK) => {
                let now = progress.load(std::sync::atomic::Ordering::Relaxed);
                if now != last {
                    last = now;
                    stalled = std::time::Duration::ZERO;
                } else {
                    stalled += CHECK;
                    if stalled >= DRAIN_DEADLINE {
                        debug!("relay drain stalled; closing both directions");
                        return Ok(now);
                    }
                }
            }
        }
    }
}

/// Relay a TCP connection between client and proxy.
///
/// This is the core forwarding function. It reads from the client and
/// writes to the proxy, and vice versa, until either side closes.
///
/// Both sides are generic over the async I/O traits so they can be plain
/// TCP sockets or TLS-wrapped streams (or boxed trait objects).
pub async fn relay_tcp<S1, S2>(
    mut client: S1,
    mut proxy: S2,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
) -> anyhow::Result<RelayStats>
where
    S1: AsyncRead + AsyncWrite + Send + Unpin,
    S2: AsyncRead + AsyncWrite + Send + Unpin,
{
    let start = tokio::time::Instant::now();

    debug!("TCP relay started: {} → {}", client_addr, target_addr);

    let result = copy_phase(&mut client, &mut proxy, None).await;
    let _ = client.shutdown().await;
    let _ = proxy.shutdown().await;
    relay_outcome(result, start, client_addr, target_addr)
}

/// Copies both directions until they finish or, with an armed `park`, until
/// one direction takes it. A parked phase shuts nothing down.
async fn copy_phase<S1, S2>(
    client: &mut S1,
    proxy: &mut S2,
    park: Option<&Park<'_>>,
) -> Result<(u64, u64), RelayError>
where
    S1: AsyncRead + AsyncWrite + Send + Unpin,
    S2: AsyncRead + AsyncWrite + Send + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut pr, mut pw) = tokio::io::split(proxy);
    let c2p_progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let p2c_progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let c2p = copy_way(&mut cr, &mut pw, c2p_progress.clone(), true, park);
    let p2c = copy_way(&mut pr, &mut cw, p2c_progress.clone(), false, park);
    tokio::pin!(c2p);
    tokio::pin!(p2c);
    let parked = || park.is_some_and(Park::taken);

    // The first direction to finish half-closes the other (inside
    // copy_way); the survivor then drains until its own EOF or until it
    // stalls for a full DRAIN_DEADLINE. An error in either direction
    // cancels the whole relay, mirroring `copy_bidirectional`. A parked
    // direction left the other suspended in a read, so dropping it is safe.
    tokio::select! {
        r = &mut c2p => match r {
            Err(e) => Err(e),
            Ok(first_n) if parked() => Ok((first_n, p2c_progress.load(Ordering::Relaxed))),
            Ok(first_n) => drain_wait(&mut p2c, &p2c_progress).await.map(|second_n| (first_n, second_n)),
        },
        r = &mut p2c => match r {
            Err(e) => Err(e),
            Ok(first_n) if parked() => Ok((c2p_progress.load(Ordering::Relaxed), first_n)),
            Ok(first_n) => drain_wait(&mut c2p, &c2p_progress).await.map(|second_n| (second_n, first_n)),
        },
    }
}

fn relay_outcome(
    result: Result<(u64, u64), RelayError>,
    start: tokio::time::Instant,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
) -> anyhow::Result<RelayStats> {
    let duration_ms = start.elapsed().as_millis() as u64;
    match result {
        Ok((c2p_bytes, p2c_bytes)) => {
            let stats = RelayStats {
                client_to_proxy: c2p_bytes,
                proxy_to_client: p2c_bytes,
                total_bytes: c2p_bytes + p2c_bytes,
                duration_ms,
            };

            debug!(
                "TCP relay complete: {} → {} ({} bytes in {}ms)",
                client_addr, target_addr, stats.total_bytes, duration_ms
            );

            Ok(stats)
        }
        Err(e) => Err(e.into_anyhow()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn saturated_relay_keeps_large_frames_and_partial_write_integrity() {
        struct FramedWriter {
            bytes: Vec<u8>,
            sizes: Vec<usize>,
            limit: usize,
            pending: bool,
        }

        impl AsyncWrite for FramedWriter {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.pending = !self.pending;
                if self.pending {
                    cx.waker().wake_by_ref();
                    return std::task::Poll::Pending;
                }
                let n = buf.len().min(self.limit);
                self.bytes.extend_from_slice(&buf[..n]);
                self.sizes.push(n);
                std::task::Poll::Ready(Ok(n))
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        let payload: Vec<u8> = (0..3 * u16::MAX as usize).map(|n| n as u8).collect();
        for limit in [u16::MAX as usize, 4093] {
            let mut source = payload.as_slice();
            let mut writer = FramedWriter {
                bytes: Vec::new(),
                sizes: Vec::new(),
                limit,
                pending: false,
            };
            let progress = Arc::new(AtomicU64::new(0));
            let copied = copy_way(&mut source, &mut writer, Arc::clone(&progress), true, None)
                .await
                .unwrap();
            assert_eq!(writer.bytes, payload);
            assert_eq!(copied, payload.len() as u64);
            assert_eq!(progress.load(Ordering::Relaxed), copied);
            if limit == u16::MAX as usize {
                // One small frame while the flow proves itself bulk, then full ones.
                let sizes = &writer.sizes;
                assert_eq!(sizes[0], RELAY_BUF_MIN);
                assert!(
                    sizes[1..sizes.len() - 1]
                        .iter()
                        .all(|&size| size == RELAY_BUF_SIZE),
                    "saturated data must not fragment into small frames: {sizes:?}"
                );
            }
        }
    }

    /// Reports the buffer room each `poll_read` is offered and serves scripted
    /// reads: a size, or `FILL` to saturate whatever room it gets.
    struct Scripted {
        reads: std::collections::VecDeque<usize>,
        offered: Vec<usize>,
    }

    const FILL: usize = usize::MAX;

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.offered.push(buf.remaining());
            if let Some(read) = self.reads.pop_front() {
                let read = read.min(buf.remaining());
                buf.put_slice(&vec![7; read]);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn offered_room(reads: &[usize]) -> Vec<usize> {
        let mut source = Scripted {
            reads: reads.iter().copied().collect(),
            offered: Vec::new(),
        };
        copy_way(
            &mut source,
            &mut tokio::io::sink(),
            Arc::new(AtomicU64::new(0)),
            true,
            None,
        )
        .await
        .unwrap();
        source.offered
    }

    #[tokio::test]
    async fn chatty_flows_keep_the_small_buffer_and_bulk_flows_grow_once() {
        let chatty = offered_room(&[1000; 50]).await;
        assert!(
            chatty.iter().all(|&room| room == RELAY_BUF_MIN),
            "{chatty:?}"
        );

        let bulk = offered_room(&[FILL, 100, 100]).await;
        assert_eq!(bulk[0], RELAY_BUF_MIN);
        assert!(
            bulk[1..].iter().all(|&room| room == RELAY_BUF_SIZE),
            "{bulk:?}"
        );
    }

    #[tokio::test]
    async fn relay_tcp_flushes_buffered_request_without_client_eof() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut client, relay_client) = tokio::io::duplex(64);
            let (relay_proxy, mut peer) = tokio::io::duplex(64);
            let address = "127.0.0.1:1".parse().unwrap();
            let (stats, (), ()) = tokio::join!(
                relay_tcp(
                    BufWriter::new(relay_client),
                    BufWriter::new(relay_proxy),
                    address,
                    address,
                ),
                async move {
                    client.write_all(b"ping").await.unwrap();
                    let mut reply = [0; 4];
                    client.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply, b"pong");
                    client.shutdown().await.unwrap();
                },
                async move {
                    let mut request = [0; 4];
                    peer.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request, b"ping");
                    peer.write_all(b"pong").await.unwrap();
                    peer.shutdown().await.unwrap();
                },
            );
            let stats = stats.unwrap();
            assert_eq!(stats.client_to_proxy, 4);
            assert_eq!(stats.proxy_to_client, 4);
        })
        .await
        .expect("buffered request/response stalled before client EOF");
    }

    async fn trojan_grpc_request_response(sniffed: bool) {
        use honk_config::node::{Node, OutboundConfig, TrojanConfig};
        use honk_outbound::proxy::{TcpOutbound, trojan::TrojanHandler};

        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(tcp).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap();
                let mut response = respond.send_response(response, false).unwrap();
                response
                    .send_data(bytes::Bytes::from_static(b"\0\0\0\0\x07\x0a\x05ready"), false)
                    .unwrap();
                let exchange = async move {
                    // Empty-password Trojan CONNECT to 1.2.3.4:53, then one request.
                    let expected = b"\0\0\0\0\x46\x0a\x44d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\r\n\x01\x01\x01\x02\x03\x04\0\x35\r\n\0\0\0\0\x06\x0a\x04ping";
                    let mut body = request.into_body();
                    let mut received = Vec::new();
                    while received.len() < expected.len() {
                        let data = body.data().await.unwrap().unwrap();
                        received.extend_from_slice(&data);
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    assert_eq!(received, expected);
                    assert!(!body.is_end_stream(), "request must arrive before client EOF");
                    response
                        .send_data(bytes::Bytes::from_static(b"\0\0\0\0\x06\x0a\x04pong"), true)
                        .unwrap();
                    drop(response);
                    while let Some(data) = body.data().await {
                        assert!(data.unwrap().is_empty(), "request must not be replayed");
                    }
                };
                tokio::join!(exchange, async move {
                    while connection.accept().await.is_some() {}
                });
            };
            let client = async move {
                let mut node = Node {
                    address: address.ip().to_string(),
                    port: address.port(),
                    outbound: OutboundConfig::Trojan(TrojanConfig::default()),
                    ..Default::default()
                };
                node.transport_mut().unwrap().transport = "grpc".into();
                let target = "1.2.3.4:53".parse().unwrap();
                let tcp = TcpStream::connect(address).await.unwrap();
                let mut proxy = TrojanHandler::new()
                    .dial_with_tcp(&node, target, None, tcp, Duration::from_secs(2))
                    .await
                    .unwrap();
                // Consume startup SETTINGS before queuing the request: its ACK
                // must not accidentally flush application bytes for the relay.
                let mut ready = [0; 5];
                proxy.stream.read_exact(&mut ready).await.unwrap();
                assert_eq!(&ready, b"ready");

                let (mut client, mut relay_client) = tokio::io::duplex(64);
                client.write_all(b"ping").await.unwrap();
                if sniffed {
                    let mut prefix = [0; 4];
                    relay_client.read_exact(&mut prefix).await.unwrap();
                    proxy.stream.write_all(&prefix).await.unwrap();
                }
                let upload = Arc::new(AtomicU64::new(0));
                let download = Arc::new(AtomicU64::new(0));
                let responses = Arc::new(AtomicUsize::new(0));
                let first_response = responses.clone();
                let (stats, ()) = tokio::join!(
                    splice::relay_auto(
                        relay_client,
                        proxy.stream,
                        address,
                        target,
                        Some(RelayProgress {
                            upload: upload.clone(),
                            download: download.clone(),
                            outbound_upload: None,
                            outbound_download: None,
                            first_response: Some(Arc::new(move || {
                                first_response.fetch_add(1, Ordering::Relaxed);
                            })),
                            on_transfer: None,
                        }),
                    ),
                    async move {
                        let mut reply = [0; 4];
                        client.read_exact(&mut reply).await.unwrap();
                        assert_eq!(&reply, b"pong");
                        client.shutdown().await.unwrap();
                    },
                );
                let stats = stats.unwrap();
                let copied_upload = if sniffed { 0 } else { 4 };
                assert_eq!(stats.client_to_proxy, copied_upload);
                assert_eq!(stats.proxy_to_client, 4);
                assert_eq!(upload.load(Ordering::Relaxed), copied_upload);
                assert_eq!(download.load(Ordering::Relaxed), 4);
                assert_eq!(responses.load(Ordering::Relaxed), 1);
            };
            tokio::join!(server, client);
        })
        .await
        .expect("Trojan gRPC request stalled before client EOF");
    }

    #[tokio::test]
    async fn relay_auto_flushes_trojan_grpc_request_without_client_eof() {
        trojan_grpc_request_response(false).await;
    }

    #[tokio::test]
    async fn relay_auto_flushes_trojan_grpc_sniff_prefix_without_more_input() {
        trojan_grpc_request_response(true).await;
    }

    /// A silent peer must not pin the copy relay forever either: after the
    /// client EOFs, the surviving direction is cut at the drain deadline.
    #[tokio::test]
    async fn test_relay_tcp_drain_deadline_reaps_silent_peer() {
        // Blackhole: accept and hold the socket, never read or write.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                std::mem::forget(stream);
            }
        });
        let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = front_listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client, client_addr) = front_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(backend).await.unwrap();
            relay_tcp(client, upstream, client_addr, backend)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(front).await.unwrap();
        let payload = vec![7u8; 64 * 1024];
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay pinned by silent peer")
            .unwrap();
        assert_eq!(stats.client_to_proxy, payload.len() as u64);
    }

    /// A survivor that keeps making progress past the deadline must not be
    /// cut: the deadline counts idle time, not total time.
    #[tokio::test]
    async fn test_relay_tcp_drain_tolerates_slow_active_survivor() {
        const CHUNKS: usize = 6;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await.unwrap();
            // Outlast several drain deadlines (500ms in tests) while always
            // staying within one deadline of the previous chunk.
            for _ in 0..CHUNKS {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                stream.write_all(&[9u8; 1024]).await.unwrap();
            }
        });
        let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = front_listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client, client_addr) = front_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(backend).await.unwrap();
            relay_tcp(client, upstream, client_addr, backend)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(front).await.unwrap();
        client.write_all(&[7u8; 4096]).await.unwrap();
        client.shutdown().await.unwrap();

        let stats = tokio::time::timeout(std::time::Duration::from_secs(10), relay)
            .await
            .expect("active survivor was cut at the deadline")
            .unwrap();
        assert_eq!(stats.proxy_to_client, (CHUNKS * 1024) as u64);
    }

    /// When the drain does cut a stalled survivor, the stats keep the
    /// bytes it moved before stalling instead of reporting zero.
    #[tokio::test]
    async fn test_relay_tcp_drain_cut_reports_progress_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sink = Vec::new();
            stream.read_to_end(&mut sink).await.unwrap();
            stream.write_all(&[9u8; 4096]).await.unwrap();
            // Then go silent forever: the drain must cut us, not pin.
            std::mem::forget(stream);
        });
        let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = front_listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client, client_addr) = front_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(backend).await.unwrap();
            relay_tcp(client, upstream, client_addr, backend)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(front).await.unwrap();
        client.write_all(&[7u8; 1024]).await.unwrap();
        client.shutdown().await.unwrap();

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .expect("relay pinned by stalled survivor")
            .unwrap();
        assert_eq!(stats.proxy_to_client, 4096);
    }

    #[tokio::test]
    async fn native_copy_accounting_survives_error_and_cancellation() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        for cancel in [false, true] {
            let (mut client, relayed_client) = tokio::io::duplex(64);
            let (upstream, mut peer) = tokio::io::duplex(64);
            let upload = Arc::new(AtomicU64::new(0));
            let aggregate = Arc::new(AtomicU64::new(17));
            let progress = RelayProgress {
                upload: upload.clone(),
                download: Arc::new(AtomicU64::new(0)),
                outbound_upload: Some(aggregate.clone()),
                outbound_download: None,
                first_response: None,
                on_transfer: None,
            };
            client.write_all(b"abcdef").await.unwrap();
            let mut peer = if cancel {
                Some(&mut peer)
            } else {
                drop(peer);
                None
            };
            let task = tokio::spawn(splice::relay_auto(
                relayed_client,
                upstream,
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
                Some(progress),
            ));
            if let Some(peer) = peer.as_mut() {
                let mut received = [0; 6];
                peer.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"abcdef");
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                assert!(task.await.unwrap().is_err());
            }
            assert_eq!(upload.load(Ordering::Relaxed), 6);
            assert_eq!(aggregate.load(Ordering::Relaxed), 23);
        }
    }
}
