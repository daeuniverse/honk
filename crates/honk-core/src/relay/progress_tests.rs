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
