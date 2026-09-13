use super::*;

async fn raw_h2_init(peer: &mut tokio::io::DuplexStream) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).await.unwrap();
    peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
}

async fn next_h2_request_stream(peer: &mut tokio::io::DuplexStream) -> u32 {
    loop {
        let mut header = [0; 9];
        peer.read_exact(&mut header).await.unwrap();
        let length =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        let mut payload = vec![0; length];
        peer.read_exact(&mut payload).await.unwrap();
        if header[3] == 4 && header[4] == 0 {
            peer.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await.unwrap();
        }
        if header[3] == 1 {
            return u32::from_be_bytes(header[5..9].try_into().unwrap());
        }
    }
}

#[tokio::test]
async fn h2_uses_configured_method_target_and_authority() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (observed, mut requests) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(sock).await.unwrap();
        while let Some(result) = connection.accept().await {
            let (request, mut respond) = result.unwrap();
            let push = http::Request::builder()
                .uri("http://probe.example/pushed")
                .body(())
                .unwrap();
            assert!(
                respond.push_request(push).is_err(),
                "probes must refuse server push"
            );
            observed
                .send((request.method().clone(), request.uri().clone()))
                .unwrap();
            let response = http::Response::builder().status(204).body(()).unwrap();
            respond.send_response(response, true).unwrap();
        }
    });
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = http_probe_request("http://probe.example:8080?source=urltest", "GET").unwrap();
    exchange_http2(stream, &request, &no_feedback(), Duration::from_secs(5))
        .await
        .expect("HTTP/2 exchange must succeed");

    let first = requests.recv().await.unwrap();
    let second = requests.recv().await.unwrap();
    assert_eq!(first.0, http::Method::HEAD);
    assert_eq!(second.0, http::Method::GET);
    for (_, uri) in [first, second] {
        assert_eq!(uri.authority().unwrap().as_str(), "probe.example:8080");
        assert_eq!(uri.path_and_query().unwrap().as_str(), "/?source=urltest");
    }
}

#[tokio::test]
async fn h2_rejects_bad_warm_status() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(sock).await.unwrap();
        let mut first = true;
        while let Some(request) = connection.accept().await {
            let (_request, mut respond) = request.unwrap();
            let status = if first { 500 } else { 204 };
            first = false;
            respond
                .send_response(
                    http::Response::builder().status(status).body(()).unwrap(),
                    true,
                )
                .unwrap();
        }
    });
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
    assert!(
        exchange_http2(stream, &request, &no_feedback(), Duration::from_secs(1))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn h2_falls_back_only_for_remote_refused_stream() {
    for (reason, healthy) in [
        (h2::Reason::REFUSED_STREAM, true),
        (h2::Reason::INTERNAL_ERROR, false),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            let mut first = true;
            while let Some(request) = connection.accept().await {
                let (_request, mut respond) = request.unwrap();
                if first {
                    first = false;
                    respond
                        .send_response(
                            http::Response::builder().status(204).body(()).unwrap(),
                            true,
                        )
                        .unwrap();
                } else {
                    respond.send_reset(reason);
                }
            }
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
        let result = exchange_http2(stream, &request, &no_feedback(), Duration::from_secs(1)).await;
        peer.abort();
        let _ = peer.await;
        assert_eq!(result.is_ok(), healthy, "RST_STREAM({reason}): {result:?}");
    }
}

#[tokio::test]
async fn h2_rejected_headers_cannot_be_overridden_by_remote_refusal() {
    let (client, mut server) = tokio::io::duplex(4096);
    let (sent, received) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        raw_h2_init(&mut server).await;
        assert_eq!(next_h2_request_stream(&mut server).await, 1);
        server
            .write_all(&[0, 0, 1, 1, 5, 0, 0, 0, 1, 0x89])
            .await
            .unwrap();
        assert_eq!(next_h2_request_stream(&mut server).await, 3);
        // HPACK :status 204 + 300 accept-encoding entries decode to 18,042 bytes.
        let mut frames = vec![0, 1, 45, 1, 4, 0, 0, 0, 3, 0x89];
        frames.extend(std::iter::repeat_n(0x90, 300));
        // Without END_STREAM, h2 can queue a local reset then overwrite it
        // with this remote refusal before the response future is polled.
        frames.extend_from_slice(&[0, 0, 4, 3, 0, 0, 0, 0, 3, 0, 0, 0, 7]);
        server.write_all(&frames).await.unwrap();
        sent.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
    let result = exchange_http2(client, &request, &no_feedback(), Duration::from_secs(1)).await;
    peer.abort();
    let _ = peer.await;
    received
        .await
        .expect("peer must deliver the measured response");
    assert!(
        result.is_err(),
        "rejected HTTP/2 headers cannot become warm success: {result:?}"
    );
}

#[tokio::test]
async fn h2_keeps_cancelled_warm_stream_until_measurement_finishes() {
    let (client, mut server) = tokio::io::duplex(4096);
    let (sent, received) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        raw_h2_init(&mut server).await;
        // Queue warm HEADERS and empty terminal DATA together, but defer the
        // DATA delivery to model bytes already in flight before cancellation.
        let warm = [0, 0, 1, 1, 4, 0, 0, 0, 1, 0x89, 0, 0, 0, 0, 1, 0, 0, 0, 1];
        assert_eq!(next_h2_request_stream(&mut server).await, 1);
        server.write_all(&warm[..10]).await.unwrap();
        assert_eq!(next_h2_request_stream(&mut server).await, 3);
        // The measured request follows warm-body Drop. h2's one-second
        // reset retention uses std::time::Instant, not Tokio's paused clock.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let mut frames = warm[10..].to_vec();
        frames.extend_from_slice(&[0, 0, 1, 1, 5, 0, 0, 0, 3, 0x89]);
        server.write_all(&frames).await.unwrap();
        sent.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
    let result = exchange_http2(client, &request, &no_feedback(), Duration::from_secs(5)).await;
    peer.abort();
    let _ = peer.await;
    received
        .await
        .expect("peer must deliver both response endings");
    let measured = result.expect("late warm completion must not fail the measured request");
    assert!(
        measured >= Duration::from_secs(1),
        "expected the delayed measured RTT, not warm fallback: {measured:?}"
    );
}

#[tokio::test]
async fn h2_falls_back_only_for_graceful_goaway() {
    for (reason, healthy) in [(0_u32, true), (1, false)] {
        let (client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            raw_h2_init(&mut server).await;
            assert_eq!(next_h2_request_stream(&mut server).await, 1);
            // Deliver :status 204 and GOAWAY together, before stream 3 can open.
            let mut frames = vec![
                0, 0, 1, 1, 5, 0, 0, 0, 1, 0x89, 0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ];
            frames.extend_from_slice(&reason.to_be_bytes());
            server.write_all(&frames).await.unwrap();
            std::future::pending::<()>().await;
        });
        let request = http_probe_request("http://probe.example/health", "HEAD").unwrap();
        let result = exchange_http2(client, &request, &no_feedback(), Duration::from_secs(1)).await;
        peer.abort();
        let _ = peer.await;
        assert_eq!(result.is_ok(), healthy, "GOAWAY({reason}): {result:?}");
    }
}

struct DropWatch<S> {
    stream: S,
    dropped: Arc<std::sync::atomic::AtomicBool>,
    block_writes: Arc<std::sync::atomic::AtomicBool>,
}

impl<S> Drop for DropWatch<S> {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DropWatch<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DropWatch<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.block_writes.load(std::sync::atomic::Ordering::Acquire) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.block_writes.load(std::sync::atomic::Ordering::Acquire) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.block_writes.load(std::sync::atomic::Ordering::Acquire) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

#[tokio::test]
async fn cancelling_stalled_h2_probe_drops_its_driver_stream() {
    let (client, server) = tokio::io::duplex(4096);
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let block_writes = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watched = DropWatch {
        stream: client,
        dropped: Arc::clone(&dropped),
        block_writes: Arc::clone(&block_writes),
    };
    let (accepted, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let (_request, _respond) = connection.accept().await.unwrap().unwrap();
        let _ = accepted.send(());
        let _held = (connection, _request, _respond);
        std::future::pending::<()>().await;
    });
    let probe = tokio::spawn(async move {
        let request = http_probe_request("http://probe.example/stall", "HEAD").unwrap();
        exchange_http2(watched, &request, &no_feedback(), Duration::from_secs(5)).await
    });
    tokio::time::timeout(Duration::from_secs(1), accepted_rx)
        .await
        .unwrap()
        .unwrap();
    block_writes.store(true, std::sync::atomic::Ordering::Release);
    probe.abort();
    let _ = probe.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !dropped.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled HTTP/2 driver must release its stream");
    server.abort();
    let _ = server.await;
}
