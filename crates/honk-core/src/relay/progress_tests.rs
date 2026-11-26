mod drain;

use super::*;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};

#[tokio::test]
async fn copy_reports_response_while_client_blocked_and_progress_before_eof() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut client, mut relay_client) = tokio::io::duplex(1);
        let (relay_proxy, mut peer) = tokio::io::duplex(64);
        relay_client.write_all(b"x").await.unwrap();
        peer.write_all(b"pong").await.unwrap();
        let responses = Arc::new(AtomicUsize::new(0));
        let response_ready = Arc::new(tokio::sync::Notify::new());
        let transferred = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let progress = RelayProgress {
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            outbound_upload: None,
            outbound_download: None,
            first_response: Some(Arc::new({
                let responses = responses.clone();
                let response_ready = response_ready.clone();
                move || {
                    responses.fetch_add(1, Ordering::Relaxed);
                    response_ready.notify_one();
                }
            })),
            on_transfer: Some(Arc::new({
                let transferred = transferred.clone();
                move |up, down| {
                    assert!(up == 0 || down == 0);
                    transferred.0.fetch_add(up, Ordering::Relaxed);
                    transferred.1.fetch_add(down, Ordering::Relaxed);
                }
            })),
        };
        let address = "127.0.0.1:1".parse().unwrap();
        let relay = tokio::spawn(splice::relay_auto(
            relay_client,
            relay_proxy,
            address,
            address,
            Some(progress),
        ));
        response_ready.notified().await;
        assert_eq!(responses.load(Ordering::Relaxed), 1);
        assert_eq!(transferred.1.load(Ordering::Relaxed), 0);
        assert!(!relay.is_finished());

        let mut prefix = [0; 1];
        client.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"x");
        for expected in [b"pong", b"more"] {
            if expected == b"more" {
                peer.write_all(expected).await.unwrap();
            }
            let mut reply = [0; 4];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, expected);
        }
        client.write_all(b"u").await.unwrap();
        let mut request = [0; 1];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"u");
        assert_eq!(transferred.0.load(Ordering::Relaxed), 1);
        assert_eq!(transferred.1.load(Ordering::Relaxed), 8);
        assert_eq!(responses.load(Ordering::Relaxed), 1);
        assert!(!relay.is_finished());

        client.shutdown().await.unwrap();
        peer.shutdown().await.unwrap();
        let stats = relay.await.unwrap().unwrap();
        assert_eq!((stats.client_to_proxy, stats.proxy_to_client), (1, 8));
        assert_eq!(transferred.0.load(Ordering::Relaxed), 1);
        assert_eq!(transferred.1.load(Ordering::Relaxed), 8);
    })
    .await
    .expect("copy observations waited for client reads or EOF");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailurePoint {
    Read,
    Write,
    BufferedFlush,
    PendingFlush,
    EofFlush,
    Shutdown,
}

struct FailAfter {
    inner: DuplexStream,
    remaining: usize,
    point: FailurePoint,
    error: Option<io::Error>,
}

impl AsyncRead for FailAfter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.point == FailurePoint::Read && self.remaining == 0 {
            return Poll::Ready(Err(self.error.take().unwrap()));
        }
        let before = buf.filled().len();
        std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        if self.point == FailurePoint::Read {
            self.remaining -= buf.filled().len() - before;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FailAfter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let fail_write = matches!(
            self.point,
            FailurePoint::Write | FailurePoint::BufferedFlush
        );
        if fail_write && self.remaining == 0 {
            return Poll::Ready(self.error.take().map_or(Ok(0), Err));
        }
        let len = if fail_write {
            bytes.len().min(self.remaining).min(3)
        } else {
            bytes.len()
        };
        let written = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, &bytes[..len]))?;
        if self.point != FailurePoint::Read {
            self.remaining = self.remaining.saturating_sub(written);
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if matches!(
            self.point,
            FailurePoint::PendingFlush | FailurePoint::EofFlush
        ) && self.remaining == 0
            && let Some(error) = self.error.take()
        {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.point == FailurePoint::Shutdown
            && self.remaining == 0
            && let Some(error) = self.error.take()
        {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("transport failure")]
struct TransportFailure(Arc<()>);

#[tokio::test]
async fn copy_errors_preserve_endpoint_origin_original_error_and_accepted_bytes() {
    use FailurePoint::*;

    tokio::time::timeout(Duration::from_secs(2), async {
        for (point, kind, errno, disconnect) in [
            (
                Read,
                ErrorKind::ConnectionReset,
                Some(libc::ECONNRESET),
                true,
            ),
            (Write, ErrorKind::BrokenPipe, None, true),
            (
                BufferedFlush,
                ErrorKind::NotConnected,
                Some(libc::ENOTCONN),
                true,
            ),
            (
                PendingFlush,
                ErrorKind::TimedOut,
                Some(libc::ETIMEDOUT),
                true,
            ),
            (
                Read,
                ErrorKind::HostUnreachable,
                Some(libc::EHOSTUNREACH),
                true,
            ),
            (
                Write,
                ErrorKind::NetworkUnreachable,
                Some(libc::ENETUNREACH),
                true,
            ),
            (
                EofFlush,
                ErrorKind::ConnectionAborted,
                Some(libc::ECONNABORTED),
                true,
            ),
            (Shutdown, ErrorKind::UnexpectedEof, None, true),
            (Read, ErrorKind::InvalidData, None, false),
            (Write, ErrorKind::WriteZero, None, false),
            (
                PendingFlush,
                ErrorKind::OutOfMemory,
                Some(libc::ENOMEM),
                false,
            ),
            (Shutdown, ErrorKind::Other, None, false),
        ] {
            for client_side in [true, false] {
                let payload = Arc::new(());
                let error = if kind == ErrorKind::WriteZero {
                    None
                } else {
                    Some(match errno {
                        Some(errno) => io::Error::from_raw_os_error(errno),
                        None => io::Error::new(kind, TransportFailure(payload.clone())),
                    })
                };
                let (fault_stream, mut fault_peer) = tokio::io::duplex(64);
                let (other_stream, mut other_peer) = tokio::io::duplex(64);
                let mut fault_stream = tokio::io::BufWriter::with_capacity(
                    if point == BufferedFlush { 64 } else { 1 },
                    FailAfter {
                        inner: fault_stream,
                        remaining: match point {
                            Write => 5,
                            BufferedFlush => 0,
                            _ => 8,
                        },
                        point,
                        error,
                    },
                );
                match point {
                    Read => fault_peer.write_all(b"abcdefgh").await.unwrap(),
                    BufferedFlush => fault_stream.write_all(b"prefix").await.unwrap(),
                    _ => {
                        other_peer.write_all(b"abcdefgh").await.unwrap();
                        if matches!(point, EofFlush | Shutdown) {
                            other_peer.shutdown().await.unwrap();
                        }
                    }
                }
                let upload = Arc::new(AtomicU64::new(0));
                let download = Arc::new(AtomicU64::new(0));
                let accepted = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
                let progress = RelayProgress {
                    upload: upload.clone(),
                    download: download.clone(),
                    outbound_upload: None,
                    outbound_download: None,
                    first_response: None,
                    on_transfer: Some(Arc::new({
                        let accepted = accepted.clone();
                        move |up, down| {
                            accepted.0.fetch_add(up, Ordering::Relaxed);
                            accepted.1.fetch_add(down, Ordering::Relaxed);
                        }
                    })),
                };
                let address = "127.0.0.1:1".parse().unwrap();
                let result = if client_side {
                    splice::relay_auto(fault_stream, other_stream, address, address, Some(progress))
                        .await
                } else {
                    splice::relay_auto(other_stream, fault_stream, address, address, Some(progress))
                        .await
                };
                let error = result
                    .unwrap_err()
                    .context("relay caller")
                    .context("connection caller");
                assert_eq!(
                    error.is::<ClientIoError>(),
                    client_side && disconnect,
                    "{point:?}, {kind:?}, client_side={client_side}: {error:#}"
                );
                let original = error.downcast_ref::<io::Error>().unwrap();
                assert_eq!(original.kind(), kind);
                assert_eq!(original.raw_os_error(), errno);
                if errno.is_none() && kind != ErrorKind::WriteZero {
                    let inner = original
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<TransportFailure>()
                        .unwrap();
                    assert!(Arc::ptr_eq(&inner.0, &payload));
                }
                let expected_accepted = match point {
                    Write => 5,
                    BufferedFlush => 0,
                    _ => 8,
                };
                let expected_read = if point == BufferedFlush { 0 } else { 8 };
                let is_upload = if point == Read {
                    client_side
                } else {
                    !client_side
                };
                assert_eq!(
                    (
                        upload.load(Ordering::Relaxed),
                        download.load(Ordering::Relaxed)
                    ),
                    if is_upload {
                        (expected_read, 0)
                    } else {
                        (0, expected_read)
                    },
                    "source-read accounting changed for {point:?}, client_side={client_side}"
                );
                assert_eq!(
                    (
                        accepted.0.load(Ordering::Relaxed),
                        accepted.1.load(Ordering::Relaxed)
                    ),
                    if is_upload {
                        (expected_accepted, 0)
                    } else {
                        (0, expected_accepted)
                    },
                    "accepted-write accounting changed for {point:?}, client_side={client_side}"
                );
                let receiver = if point == Read {
                    &mut other_peer
                } else {
                    &mut fault_peer
                };
                let mut received = Vec::new();
                receiver.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, &b"abcdefgh"[..expected_accepted as usize]);
            }
        }
    })
    .await
    .expect("copy failure did not terminate relay");
}

#[tokio::test(start_paused = true)]
async fn websocket_copy_drains_after_client_eof_but_not_after_client_error() {
    use futures_util::StreamExt;
    use honk_config::node::{Node, OutboundConfig, TrojanConfig};
    use honk_outbound::proxy::{TcpOutbound, TunnelDialOptions, trojan::TrojanHandler};
    use honk_outbound::runtime::NodeRuntime;
    use tokio::sync::oneshot;
    use tokio_tungstenite::tungstenite::Message;

    #[derive(Debug)]
    struct FinalFrameWriter {
        inner: tokio::io::WriteHalf<DuplexStream>,
        blocked: Option<oneshot::Sender<()>>,
        release: oneshot::Receiver<()>,
        drip: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl AsyncWrite for FinalFrameWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            // The only masked four-byte application frame is "last".
            if bytes.starts_with(&[0x82, 0x84]) {
                if let Some(blocked) = self.blocked.take() {
                    blocked.send(()).unwrap();
                }
                if !self.release.is_terminated() {
                    std::task::ready!(Pin::new(&mut self.release).poll(cx)).unwrap();
                }
            }
            if self.blocked.is_none()
                && let Some(delay) = &mut self.drip
            {
                std::task::ready!(delay.as_mut().poll(cx));
                delay
                    .as_mut()
                    .reset(tokio::time::Instant::now() + DRAIN_DEADLINE / 4);
                return Pin::new(&mut self.inner).poll_write(cx, &bytes[..1]);
            }
            Pin::new(&mut self.inner).poll_write(cx, bytes)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    let mut node = Node {
        name: "ws".into(),
        address: "127.0.0.1:80".into(),
        host: "127.0.0.1".into(),
        port: 80,
        outbound: OutboundConfig::Trojan(TrojanConfig {
            password: Some("secret".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    node.transport_mut().unwrap().transport = "ws".into();
    node.id = node.derive_id();
    let runtime = NodeRuntime::try_ephemeral(&node).unwrap();
    let addr = "127.0.0.1:80".parse().unwrap();
    #[derive(Clone, Copy, PartialEq)]
    enum End {
        Released,
        Idle,
        ClientError,
        CarrierDrip,
    }
    for end in [End::Released, End::Idle, End::ClientError, End::CarrierDrip] {
        tokio::time::timeout(DRAIN_DEADLINE * 4, async {
            let (physical, peer) = tokio::io::duplex(4096);
            let (rd, wr) = tokio::io::split(physical);
            let (blocked, reached) = oneshot::channel();
            let (release, open) = oneshot::channel();
            let gate = FinalFrameWriter {
                inner: wr,
                blocked: Some(blocked),
                release: open,
                drip: (end == End::CarrierDrip)
                    .then(|| Box::pin(tokio::time::sleep(DRAIN_DEADLINE / 4))),
            };
            let (proxy, peer) = tokio::join!(
                TrojanHandler.dial_over(
                    runtime.clone(),
                    Box::new(tokio::io::join(rd, gate)),
                    addr,
                    None,
                    TunnelDialOptions::new(Duration::from_secs(2))
                ),
                tokio_tungstenite::accept_async(peer),
            );
            let mut peer = peer.unwrap();
            let header = peer.next().await.unwrap().unwrap().into_data();
            assert_eq!(&header[56..], b"\r\n\x01\x01\x7f\0\0\x01\0\x50\r\n");

            let (mut client, relay_client) = tokio::io::duplex(64);
            let relay_client = FailAfter {
                inner: relay_client,
                remaining: 5,
                point: FailurePoint::Read,
                error: Some(io::Error::from_raw_os_error(libc::ECONNRESET)),
            };
            let relay = tokio::spawn(relay_tcp(relay_client, proxy.unwrap().stream, addr, addr));
            client.write_all(b"last").await.unwrap();
            reached.await.unwrap();
            let start = tokio::time::Instant::now();
            if end == End::ClientError {
                client.write_all(b"!").await.unwrap();
            } else {
                client.shutdown().await.unwrap();
            }

            if end == End::Released {
                tokio::time::sleep(DRAIN_DEADLINE / 2).await;
                assert!(!relay.is_finished());
                release.send(()).unwrap();
                let stats = relay.await.unwrap().unwrap();
                assert_eq!(stats.client_to_proxy, 4);
                assert_eq!(
                    peer.next().await.unwrap().unwrap().into_data().as_ref(),
                    b"last"
                );
                assert_eq!(peer.next().await.unwrap().unwrap(), Message::Close(None));
            } else if end == End::CarrierDrip {
                // The WS worker is writing one real byte per quarter-deadline,
                // but the copy directions have made no new byte progress.
                release.send(()).unwrap();
                let stats = relay.await.unwrap().unwrap();
                assert_eq!(stats.client_to_proxy, 4);
                let mut raw = Vec::new();
                peer.get_mut().read_to_end(&mut raw).await.unwrap();
                assert!(raw.starts_with(&[0x82, 0x84]));
                assert!(
                    raw.len() < 10,
                    "the entire frame drained despite an idle copy"
                );
            } else {
                let result = relay.await.unwrap();
                if end == End::ClientError {
                    let err = result.unwrap_err();
                    assert!(err.is::<ClientIoError>());
                    assert_eq!(
                        err.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                        Some(libc::ECONNRESET)
                    );
                    assert!(start.elapsed() < DRAIN_DEADLINE);
                } else {
                    assert_eq!(result.unwrap().client_to_proxy, 4);
                    assert!(start.elapsed() >= DRAIN_DEADLINE);
                }
                assert!(release.send(()).is_err());
                let mut wire = Vec::new();
                peer.get_mut().read_to_end(&mut wire).await.unwrap();
                assert!(wire.is_empty());
            }
        })
        .await
        .expect("copy relay outlived the existing drain deadline");
    }
}
