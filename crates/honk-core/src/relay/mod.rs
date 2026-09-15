//! TCP relay engine.
//!
//! Handles bidirectional data relay between a client connection and a
//! proxy connection. Wrapped streams (TLS/protocol) use async I/O with
//! a pair of `tokio::io::copy` pumps; when both ends are plain `TcpStream`s
//! (direct connections), the `splice` module relays them zero-copy via
//! `splice(2)` with automatic fallback to the copy path.
//!
//! ## Architecture
//!
//! ```text
//! Client ◄═══════► honk-core ◄═══════► Proxy Server ◄═══════► Target
//!          (TCP)              (SOCKS5)                  (TCP)
//! ```

pub mod splice;

use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

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

/// Live relay progress shared with connection accounting and optional
/// first-response notification.
#[derive(Clone)]
pub struct RelayProgress {
    pub upload: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub download: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub first_response: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

pub type OptionalRelayProgress = Option<RelayProgress>;

/// AsyncRead wrapper that counts bytes read from the inner stream into a
/// shared counter. Writes pass through untouched.
pub(crate) struct ReadCounter<S> {
    inner: S,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    on_progress: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl<S> ReadCounter<S> {
    pub(crate) fn wrap(
        inner: S,
        counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
        on_progress: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        Self {
            inner,
            counter,
            on_progress,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ReadCounter<S> {
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
                if let Some(callback) = self.on_progress.take() {
                    callback();
                }
            }
        }
        poll
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ReadCounter<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
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
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Grace window for the surviving direction after the first EOF, counted
/// as idle time: any byte of progress resets it. See
/// [`splice::DRAIN_DEADLINE`] for why the drain must be bounded.
const DRAIN_DEADLINE: std::time::Duration = splice::DRAIN_DEADLINE;

/// Copy one direction until EOF, then half-close the destination's write
/// side (same contract as `copy_bidirectional`). Bytes read are counted
/// into `progress` so the drain supervisor can tell a stalled survivor
/// from an active one.
async fn copy_way<R, W>(
    rd: &mut R,
    wr: &mut W,
    progress: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Sniffing or protocol setup may already have buffered bytes before the
    // copier starts; copy only flushes writes it performs itself.
    wr.flush().await?;
    let mut rd = ReadCounter::wrap(rd, progress, None);
    let n = tokio::io::copy(&mut rd, wr).await?;
    wr.shutdown().await?;
    Ok(n)
}

/// Wait out the surviving direction after its peer finished. The survivor
/// is cut only after a full [`DRAIN_DEADLINE`] without any byte progress —
/// a slow but active download may far exceed the deadline and must not be
/// interrupted. A cut survivor reports the counter's final value, so the
/// bytes it did move are not lost from the stats.
async fn drain_wait(
    f: &mut (impl std::future::Future<Output = std::io::Result<u64>> + Unpin),
    progress: &std::sync::atomic::AtomicU64,
) -> std::io::Result<u64> {
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

    let (mut cr, mut cw) = tokio::io::split(&mut client);
    let (mut pr, mut pw) = tokio::io::split(&mut proxy);
    let c2p_progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let p2c_progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Boxed so dropping them actually releases the stream borrows before
    // the final shutdown calls.
    let mut c2p = Box::pin(copy_way(&mut cr, &mut pw, c2p_progress.clone()));
    let mut p2c = Box::pin(copy_way(&mut pr, &mut cw, p2c_progress.clone()));

    // The first direction to finish half-closes the other (inside
    // copy_way); the survivor then drains until its own EOF or until it
    // stalls for a full DRAIN_DEADLINE. An error in either direction
    // cancels the whole relay, mirroring `copy_bidirectional`.
    let result: std::io::Result<(u64, u64)> = tokio::select! {
        r = &mut c2p => match r {
            Err(e) => Err(e),
            Ok(first_n) => drain_wait(&mut p2c, &p2c_progress).await.map(|second_n| (first_n, second_n)),
        },
        r = &mut p2c => match r {
            Err(e) => Err(e),
            Ok(first_n) => drain_wait(&mut c2p, &c2p_progress).await.map(|second_n| (second_n, first_n)),
        },
    };
    drop(c2p);
    drop(p2c);

    let _ = client.shutdown().await;
    let _ = proxy.shutdown().await;

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
        Err(e) => {
            if !is_ignorable_connection_error(&e) {
                warn!(
                    "TCP relay error for {} → {}: {}",
                    client_addr, target_addr, e
                );
            }
            Err(e.into())
        }
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
                            first_response: Some(Arc::new(move || {
                                first_response.fetch_add(1, Ordering::Relaxed);
                            })),
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
}
