use super::{grpc_peer::*, wrap_grpc, wrap_transport};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Debug, Default)]
struct IoControl {
    mode: AtomicU8,
    waker: futures_util::task::AtomicWaker,
    dropped: AtomicBool,
}

#[derive(Debug)]
struct ControlledIo {
    inner: tokio::io::DuplexStream,
    control: Arc<IoControl>,
    dribble: bool,
}

impl Drop for ControlledIo {
    fn drop(&mut self) {
        self.control.dropped.store(true, Ordering::Release);
    }
}

impl AsyncRead for ControlledIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.dribble || buf.remaining() == 0 {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let mut byte = [0];
        let mut short = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.inner).poll_read(cx, &mut short) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(short.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.control.waker.register(cx.waker());
        match self.control.mode.load(Ordering::Acquire) {
            1 => return Poll::Pending,
            2 => return Poll::Ready(Ok(0)),
            _ => {}
        }
        let len = if self.dribble {
            buf.len().min(1)
        } else {
            buf.len()
        };
        Pin::new(&mut self.inner).poll_write(cx, &buf[..len])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn decode_messages(mut wire: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    while !wire.is_empty() {
        assert_eq!(wire[0], 0, "compressed gun message");
        let len = u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize;
        let message = &wire[5..5 + len];
        assert_eq!(message[0], 0x0a);
        let mut content_len = 0;
        let mut offset = 1;
        for shift in (0..usize::BITS).step_by(7) {
            let byte = message[offset];
            offset += 1;
            content_len |= ((byte & 0x7f) as usize) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        assert_eq!(offset + content_len, message.len());
        payload.extend_from_slice(&message[offset..]);
        wire = &wire[5 + len..];
    }
    payload
}

#[tokio::test]
async fn grpc_queued_write_owns_bytes_and_cancelled_write_owns_nothing() {
    // h2 copies small DATA into its encoder but chains larger buffers.
    for source_len in [5, 16 * 1024] {
        let (client, mut server) = tokio::io::duplex(128);
        let control = Arc::new(IoControl::default());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let serve = async {
            read_request(&mut server).await;
            server.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
            ready_tx.send(()).unwrap();
            let mut wire = Vec::new();
            loop {
                let (kind, flags, stream, payload) = read_frame(&mut server).await;
                if kind == DATA && stream == 1 {
                    wire.extend_from_slice(&payload);
                    if flags & END_STREAM != 0 {
                        break;
                    }
                }
            }
            let mut response = frame(HEADERS, END_HEADERS, 1, &response_headers());
            response.extend(data(b"pong"));
            response.extend(trailers(b"0"));
            server.write_all(&response).await.unwrap();
            let _ = done_rx.await;
            decode_messages(&wire)
        };
        let consume = async {
            let inner = ControlledIo {
                inner: client,
                control: control.clone(),
                dribble: false,
            };
            let mut stream = wrap_grpc(&grpc_node(), Box::new(inner)).await.unwrap();
            ready_rx.await.unwrap();
            control.mode.store(1, Ordering::Release);
            let mut source = vec![b'a'; source_len];
            let accepted = stream.write(&source).await.unwrap();
            assert!(accepted > 0 && accepted <= source.len());
            source.fill(b'z');
            assert!(futures_util::poll!(std::pin::pin!(stream.write(b"cancelled"))).is_pending());
            assert!(futures_util::poll!(std::pin::pin!(stream.flush())).is_pending());
            control.mode.store(0, Ordering::Release);
            control.waker.wake();
            stream.write_all(b"x").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"pong");
            assert_eq!(
                stream.write(b"late").await.unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            assert_eq!(stream.write(&[]).await.unwrap(), 0);
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            drop(stream);
            assert!(control.dropped.load(Ordering::Acquire));
            let _ = done_tx.send(());
            accepted
        };
        let (accepted, received) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(consume, serve)
        })
        .await
        .expect("cancelled write exchange stalled");
        let mut expected = vec![b'a'; accepted];
        expected.push(b'x');
        assert_eq!(received, expected);
    }
}

#[tokio::test]
async fn grpc_inner_write_zero_is_a_retained_error_and_drop_closes_transport() {
    let (client, mut server) = tokio::io::duplex(4096);
    let control = Arc::new(IoControl::default());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let serve = async {
        read_request(&mut server).await;
        server.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
        ready_tx.send(()).unwrap();
        let mut remainder = Vec::new();
        server.read_to_end(&mut remainder).await.unwrap();
    };
    let consume = async {
        let inner = ControlledIo {
            inner: client,
            control: control.clone(),
            dribble: false,
        };
        let mut stream = wrap_grpc(&grpc_node(), Box::new(inner)).await.unwrap();
        ready_rx.await.unwrap();
        control.mode.store(2, Ordering::Release);
        let error = match stream.write(b"queued").await {
            Ok(_) => stream.flush().await.unwrap_err(),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
        let repeated = terminal_error(&mut stream).await;
        assert_eq!(repeated.kind(), std::io::ErrorKind::WriteZero);
        drop(stream);
        assert!(control.dropped.load(Ordering::Acquire));
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("write-zero exchange stalled");
}

async fn h2_roundtrip(dribble: bool, window: u32) {
    let (client, server) = tokio::io::duplex(4096);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let payload = vec![0x5a; 512];
    let serve = async {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(window)
            .handshake::<_, bytes::Bytes>(server)
            .await
            .unwrap();
        let (request, mut respond) = connection.accept().await.expect("request").unwrap();
        let exchange = async {
            let mut body = request.into_body();
            let mut wire = Vec::new();
            while let Some(data) = body.data().await {
                let data = data.unwrap();
                wire.extend_from_slice(&data);
                body.flow_control().release_capacity(data.len()).unwrap();
            }
            assert_eq!(decode_messages(&wire), payload);
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            body.send_data(gun_message(b"pong").into(), false).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            body.send_trailers(trailers).unwrap();
            let _ = done_rx.await;
        };
        tokio::join!(exchange, async {
            while connection.accept().await.is_some() {}
        });
    };
    let consume = async {
        let inner = ControlledIo {
            inner: client,
            control: Default::default(),
            dribble,
        };
        let mut stream = wrap_grpc(&grpc_node(), Box::new(inner)).await.unwrap();
        // The server intentionally withholds response headers until request EOF.
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"pong");
        let _ = done_tx.send(());
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("small-window/short-I/O roundtrip stalled");
}

#[tokio::test]
async fn grpc_short_reads_and_writes_preserve_roundtrip() {
    h2_roundtrip(true, 65_535).await;
}

#[tokio::test]
async fn grpc_small_positive_windows_and_request_half_close_preserve_response() {
    for window in [1, 128] {
        h2_roundtrip(false, window).await;
    }
}

#[tokio::test]
async fn grpc_request_path_and_authority_length_boundaries() {
    let long_authority = "a".repeat(300);
    for (service_len, host, authority) in [
        (195, "example.com", "example.com"),
        (122, "example.com", "example.com"),
        (1, long_authority.as_str(), long_authority.as_str()),
        (1, "::1", "[::1]"),
        (1, "[::1]", "[::1]"),
    ] {
        let mut node = grpc_node();
        node.host = host.to_owned();
        node.transport_mut().unwrap().grpc_service = Some("s".repeat(service_len));
        let (client, server) = tokio::io::duplex(4096);
        let serve = async {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, _) = connection.accept().await.expect("gRPC request").unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.headers()["content-type"], "application/grpc");
            assert_eq!(request.headers()["te"], "trailers");
            assert_eq!(
                request.uri().path(),
                format!("/{}/Tun", "s".repeat(service_len))
            );
            assert_eq!(request.uri().authority().unwrap().as_str(), authority);
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            let (stream, ()) = tokio::join!(wrap_grpc(&node, Box::new(client)), serve);
            stream.unwrap();
        })
        .await
        .expect("request headers stalled awaiting a response");
    }
}

#[tokio::test]
async fn grpc_request_encodes_service_path() {
    let mut node = grpc_node();
    node.transport_mut().unwrap().grpc_service = Some("svc 雪%20name".into());
    let (client, server) = tokio::io::duplex(4096);
    let serve = async {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let (request, _) = connection.accept().await.expect("gRPC request").unwrap();
        assert_eq!(request.uri().path(), "/svc%20%E9%9B%AA%20name/Tun");
        assert_eq!(request.uri().authority().unwrap().as_str(), "127.0.0.1");
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::try_join!(wrap_grpc(&node, Box::new(client)), async {
            serve.await;
            Ok::<_, anyhow::Error>(())
        },)
        .unwrap();
    })
    .await
    .expect("request headers stalled awaiting a response");
}

#[tokio::test]
async fn grpc_transport_roundtrip_through_dialer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut node = super::transport_node(port);
    let transport = node.transport_mut().unwrap();
    transport.transport = "grpc".into();
    transport.grpc_service = Some("testSvc".into());
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let serve = async {
        let (server, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(server).await.unwrap();
        let (request, mut respond) = connection.accept().await.expect("request").unwrap();
        assert_eq!(request.uri().path(), "/testSvc/Tun");
        assert_eq!(request.uri().authority().unwrap().as_str(), "127.0.0.1");
        let exchange = async {
            let mut body = request.into_body();
            let mut wire = Vec::new();
            while let Some(data) = body.data().await {
                wire.extend_from_slice(&data.unwrap());
            }
            assert_eq!(decode_messages(&wire), b"hello");
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            body.send_data(gun_message(b"world").into(), false).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            body.send_trailers(trailers).unwrap();
            let _ = done_rx.await;
        };
        tokio::join!(exchange, async {
            while connection.accept().await.is_some() {}
        });
    };
    let consume = async {
        let mut stream = wrap_transport(&node, None, Duration::from_secs(3))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"world");
        let _ = done_tx.send(());
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("dialed gRPC roundtrip stalled");
}

#[tokio::test]
async fn grpc_flush_waits_for_data_held_by_a_later_zero_window() {
    let (client, mut server) = tokio::io::duplex(4096);
    let control = Arc::new(IoControl::default());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (queued_tx, queued_rx) = tokio::sync::oneshot::channel();
    let (updated_tx, updated_rx) = tokio::sync::oneshot::channel();
    let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let serve = async {
        read_request(&mut server).await;
        server.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
        ready_tx.send(()).unwrap();
        queued_rx.await.unwrap();
        let mut settings = vec![0, 4];
        settings.extend_from_slice(&0u32.to_be_bytes());
        let mut response = frame(SETTINGS, 0, 0, &settings);
        response.extend(frame(HEADERS, END_HEADERS, 1, &response_headers()));
        response.extend(data(b"ready"));
        server.write_all(&response).await.unwrap();
        updated_tx.send(()).unwrap();
        blocked_rx.await.unwrap();
        server
            .write_all(&frame(8, 0, 1, &65_535u32.to_be_bytes()))
            .await
            .unwrap();
        let mut wire = Vec::new();
        loop {
            let (kind, flags, stream, payload) = read_frame(&mut server).await;
            if kind == DATA && stream == 1 {
                wire.extend_from_slice(&payload);
                if flags & END_STREAM != 0 {
                    break;
                }
            }
        }
        assert_eq!(decode_messages(&wire), b"queued");
        server.write_all(&trailers(b"0")).await.unwrap();
        let _ = done_rx.await;
    };
    let consume = async {
        let inner = ControlledIo {
            inner: client,
            control: control.clone(),
            dribble: false,
        };
        let mut stream = wrap_grpc(&grpc_node(), Box::new(inner)).await.unwrap();
        ready_rx.await.unwrap();
        control.mode.store(1, Ordering::Release);
        assert_eq!(stream.write(b"queued").await.unwrap(), 6);
        queued_tx.send(()).unwrap();
        updated_rx.await.unwrap();
        let mut marker = [0; 5];
        stream.read_exact(&mut marker).await.unwrap();
        assert_eq!(&marker, b"ready");
        control.mode.store(0, Ordering::Release);
        control.waker.wake();
        assert!(
            futures_util::poll!(std::pin::pin!(stream.flush())).is_pending(),
            "flush discarded flow-controlled DATA"
        );
        blocked_tx.send(()).unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut marker).await.unwrap(), 0);
        let _ = done_tx.send(());
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("zero-window flush exchange stalled");
}

#[tokio::test]
async fn grpc_read_driver_wakes_a_different_tasks_pending_flush() {
    let (client, mut server) = tokio::io::duplex(4096);
    let control = Arc::new(IoControl::default());
    let inner = ControlledIo {
        inner: client,
        control: control.clone(),
        dribble: false,
    };
    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        wrap_grpc(&grpc_node(), Box::new(inner)),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), read_request(&mut server))
        .await
        .unwrap();
    server.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
    control.mode.store(1, Ordering::Release);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (queued_tx, queued_rx) = tokio::sync::oneshot::channel();
    let (reading_tx, reading_rx) = tokio::sync::oneshot::channel();
    let (flushed_tx, flushed_rx) = tokio::sync::oneshot::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        writer.write_all(b"queued").await.unwrap();
        assert!(futures_util::poll!(std::pin::pin!(writer.flush())).is_pending());
        queued_tx.send(()).unwrap();
        writer.flush().await.unwrap();
        flushed_tx.send(()).unwrap();
    });
    tasks.spawn(async move {
        queued_rx.await.unwrap();
        let mut response = Vec::new();
        assert!(
            futures_util::poll!(std::pin::pin!(reader.read_to_end(&mut response))).is_pending()
        );
        reading_tx.send(()).unwrap();
        reader.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"pong");
        let _ = done_tx.send(());
    });
    let serve = async {
        reading_rx.await.unwrap();
        // Only the reader owns the physical-I/O waker at this point.
        control.mode.store(0, Ordering::Release);
        control.waker.wake();
        let mut wire = Vec::new();
        while wire.len() < gun_message(b"queued").len() {
            let (kind, _, stream, payload) = read_frame(&mut server).await;
            if kind == DATA && stream == 1 {
                wire.extend_from_slice(&payload);
            }
        }
        assert_eq!(decode_messages(&wire), b"queued");
        flushed_rx.await.unwrap();
        let mut response = frame(HEADERS, END_HEADERS, 1, &response_headers());
        response.extend(data(b"pong"));
        response.extend(trailers(b"0"));
        server.write_all(&response).await.unwrap();
        let _ = done_rx.await;
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(serve, async {
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
    })
    .await
    .expect("read driver failed to wake the flushing task");
}

#[tokio::test]
async fn grpc_receive_window_allows_response_beyond_http2_default() {
    let (client, server) = tokio::io::duplex(4096);
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let payload = vec![0x5a; 128 * 1024];
    let serve = async {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let (_, mut respond) = connection.accept().await.expect("request").unwrap();
        let exchange = async {
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            let message = gun_message(&payload);
            body.reserve_capacity(message.len());
            while body.capacity() < message.len() {
                std::future::poll_fn(|cx| body.poll_capacity(cx))
                    .await
                    .unwrap()
                    .unwrap();
            }
            body.send_data(message.into(), false).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            body.send_trailers(trailers).unwrap();
            let _ = done_rx.await;
        };
        tokio::join!(exchange, async {
            while connection.accept().await.is_some() {}
        });
    };
    let consume = async {
        let mut stream = wrap_grpc(&grpc_node(), Box::new(client)).await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        let _ = done_tx.send(());
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("large receive-window exchange stalled");
}

#[tokio::test]
async fn grpc_dropping_unfinished_stream_closes_its_transport() {
    let (client, mut server) = tokio::io::duplex(4096);
    let control = Arc::new(IoControl::default());
    let serve = async {
        read_request(&mut server).await;
        let mut remaining = Vec::new();
        server.read_to_end(&mut remaining).await.unwrap();
    };
    let consume = async {
        let inner = ControlledIo {
            inner: client,
            control: control.clone(),
            dribble: false,
        };
        let stream = wrap_grpc(&grpc_node(), Box::new(inner)).await.unwrap();
        drop(stream);
        assert!(control.dropped.load(Ordering::Acquire));
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(consume, serve);
    })
    .await
    .expect("dropping the wrapper left its physical transport open");
}
