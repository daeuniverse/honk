use super::test_hook::{StateGuard, TEST_LOCK};
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn observed_progress() -> (crate::relay::RelayProgress, Arc<(AtomicU64, AtomicU64)>) {
    let accepted = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let totals = accepted.clone();
    let progress = crate::relay::RelayProgress {
        upload: Arc::new(AtomicU64::new(0)),
        download: Arc::new(AtomicU64::new(0)),
        first_response: None,
        on_transfer: Some(Arc::new(move |up, down| {
            assert!(up == 0 || down == 0);
            totals.0.fetch_add(up, Ordering::Relaxed);
            totals.1.fetch_add(down, Ordering::Relaxed);
        })),
    };
    (progress, accepted)
}

/// Start a TCP echo server (writes back everything it reads, closes on
/// EOF) and return its address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Start a server that reads until EOF, then sends `trailer` and
/// closes. Used to verify half-close propagation.
async fn spawn_read_then_trailer(trailer: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut sink = Vec::new();
                let _ = stream.read_to_end(&mut sink).await;
                let _ = stream.write_all(trailer).await;
                // Dropping the stream closes the socket (FIN).
            });
        }
    });
    addr
}

/// Accept one connection on a fresh listener, dial `backend`, and relay
/// between them with [`splice_bidirectional`].
async fn spawn_splice_front(
    backend: SocketAddr,
) -> (SocketAddr, tokio::task::JoinHandle<io::Result<(u64, u64)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = listener.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(backend).await.unwrap();
        splice_bidirectional(client, upstream).await
    });
    (front, relay)
}

#[test]
fn test_is_unsupported_errno() {
    assert!(is_unsupported_errno(&io::Error::from_raw_os_error(
        libc::EINVAL
    )));
    assert!(is_unsupported_errno(&io::Error::from_raw_os_error(
        libc::ENOSYS
    )));
    assert!(is_unsupported_errno(&io::Error::from_raw_os_error(
        libc::EXDEV
    )));
    assert!(!is_unsupported_errno(&io::Error::from_raw_os_error(
        libc::ECONNRESET
    )));
    assert!(!is_unsupported_errno(&io::Error::from_raw_os_error(
        libc::EAGAIN
    )));
    assert!(!is_unsupported_errno(&io::Error::other("synthetic")));
}

/// Two active directions are bounded to four private FDs and 128 KiB of
/// requested pipe pages per full-duplex connection, down from the prior
/// 512 KiB request. Pipes are never shared, so closing a connection
/// cannot expose staged bytes to another one.
#[test]
fn test_full_duplex_pipe_resource_bound() {
    let _lock = TEST_LOCK.blocking_lock();
    let client_to_upstream = Pipe::new().expect("create client pipe");
    let upstream_to_client = Pipe::new().expect("create upstream pipe");
    assert_ne!(
        client_to_upstream.read.as_raw_fd(),
        client_to_upstream.write.as_raw_fd()
    );
    assert_ne!(
        upstream_to_client.read.as_raw_fd(),
        upstream_to_client.write.as_raw_fd()
    );
    assert!(
        client_to_upstream.capacity <= PIPE_SIZE && upstream_to_client.capacity <= PIPE_SIZE,
        "kernel pipe capacity must remain within the requested per-direction bound"
    );
    assert!(
        client_to_upstream.capacity + upstream_to_client.capacity <= 2 * PIPE_SIZE,
        "full-duplex splice relay exceeds its 128 KiB pipe-page bound"
    );
}

/// Bidirectional transfer larger than any pipe capacity, with data
/// integrity and per-direction byte counts verified.
#[tokio::test]
async fn test_splice_bidirectional_large_transfer() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();

    let echo = spawn_echo().await;
    let (front, relay) = spawn_splice_front(echo).await;

    let client = TcpStream::connect(front).await.unwrap();
    let data = pattern(4 * 1024 * 1024);
    let expected = data.clone();
    let (mut rd, mut wr) = client.into_split();

    let writer = tokio::spawn(async move {
        wr.write_all(&data).await.unwrap();
        // Half-close: the echo server sees EOF, closes, and the relay
        // must complete on its own.
        wr.shutdown().await.unwrap();
    });

    let mut received = Vec::with_capacity(expected.len());
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        rd.read_to_end(&mut received),
    )
    .await
    .expect("client read hung")
    .unwrap();
    writer.await.unwrap();

    assert_eq!(received.len(), expected.len());
    assert!(received == expected, "echoed data corrupted");

    let (c2p, p2c) = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("relay task hung")
        .unwrap()
        .unwrap();
    assert_eq!(c2p, expected.len() as u64);
    assert_eq!(p2c, expected.len() as u64);
}

/// The client FINs its upload first; data already in flight from the
/// server (sent after it sees EOF) must still be delivered — the
/// reverse direction must survive the forward direction's EOF.
#[tokio::test]
async fn test_splice_half_close_propagation() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();

    let trailer: &'static [u8] = b"server trailer after client EOF";
    let backend = spawn_read_then_trailer(trailer).await;
    let (front, relay) = spawn_splice_front(backend).await;

    let mut client = TcpStream::connect(front).await.unwrap();
    let upload = pattern(1024 * 1024);
    client.write_all(&upload).await.unwrap();
    // Client half-closes; the trailer must still arrive.
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut received),
    )
    .await
    .expect("client read hung — half-close not propagated")
    .unwrap();
    assert_eq!(received, trailer);

    let (c2p, p2c) = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("relay task hung")
        .unwrap()
        .unwrap();
    assert_eq!(c2p, upload.len() as u64);
    assert_eq!(p2c, trailer.len() as u64);
}

/// A silent peer must not pin the relay forever: after the client
/// EOFs, the surviving direction is cut at the drain deadline.
#[tokio::test]
async fn test_splice_drain_deadline_reaps_silent_peer() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();

    // Blackhole: accept and hold the socket, never read or write.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            std::mem::forget(stream);
        }
    });
    let (front, relay) = spawn_splice_front(backend).await;

    let mut client = TcpStream::connect(front).await.unwrap();
    let payload = pattern(64 * 1024);
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();

    let (c2p, _p2c) = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("relay pinned by silent peer")
        .unwrap()
        .unwrap();
    assert_eq!(c2p, payload.len() as u64);
}

/// `relay_splice` produces the same `RelayStats` shape as the copy path.
#[tokio::test]
async fn test_relay_splice_stats_match_copy_semantics() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    assert!(splice_available());

    let echo = spawn_echo().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = listener.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (mut client, client_addr) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(echo).await.unwrap();
        relay_splice(&mut client, upstream, client_addr, echo, None)
            .await
            .unwrap()
    });

    let mut client = TcpStream::connect(front).await.unwrap();
    let payload = b"stats accounting roundtrip";
    client.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
    client.shutdown().await.unwrap();

    let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("relay task hung")
        .unwrap();
    assert_eq!(stats.client_to_proxy, payload.len() as u64);
    assert_eq!(stats.proxy_to_client, payload.len() as u64);
    assert_eq!(stats.total_bytes, 2 * payload.len() as u64);
    assert!(splice_available());
}

/// Live progress counters are incremented as data flows and end up equal
/// to the final RelayStats (splice path).
#[tokio::test]
async fn test_relay_splice_live_progress_matches_stats() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    assert!(splice_available());

    let echo = spawn_echo().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = listener.local_addr().unwrap();
    let (progress, accepted) = observed_progress();
    let (up, down) = (progress.upload.clone(), progress.download.clone());
    let relay = tokio::spawn(async move {
        let (mut client, client_addr) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(echo).await.unwrap();
        relay_splice(&mut client, upstream, client_addr, echo, Some(progress)).await
    });

    let mut client = TcpStream::connect(front).await.unwrap();
    let payload = pattern(512 * 1024);
    client.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
    assert_eq!(accepted.0.load(Ordering::Relaxed), payload.len() as u64);
    assert_eq!(accepted.1.load(Ordering::Relaxed), payload.len() as u64);
    assert!(!relay.is_finished());
    client.shutdown().await.unwrap();

    let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("relay task hung")
        .unwrap()
        .unwrap();
    assert_eq!(
        up.load(Ordering::Relaxed),
        stats.client_to_proxy,
        "live upload counter must match final stats"
    );
    assert_eq!(
        down.load(Ordering::Relaxed),
        stats.proxy_to_client,
        "live download counter must match final stats"
    );
    assert_eq!(accepted.0.load(Ordering::Relaxed), stats.client_to_proxy);
    assert_eq!(accepted.1.load(Ordering::Relaxed), stats.proxy_to_client);
}

/// Live progress counters work the same through the copy relay
/// (`relay_auto` with wrapped streams).
#[tokio::test]
async fn test_relay_auto_live_progress_matches_stats() {
    let echo = spawn_echo().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = listener.local_addr().unwrap();
    let (progress, accepted) = observed_progress();
    let (up, down) = (progress.upload.clone(), progress.download.clone());
    let relay = tokio::spawn(async move {
        let (client, client_addr) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(echo).await.unwrap();
        relay_auto(client, upstream, client_addr, echo, Some(progress)).await
    });

    let mut client = TcpStream::connect(front).await.unwrap();
    let payload = pattern(256 * 1024);
    client.write_all(&payload).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
    assert_eq!(accepted.0.load(Ordering::Relaxed), payload.len() as u64);
    assert_eq!(accepted.1.load(Ordering::Relaxed), payload.len() as u64);
    assert!(!relay.is_finished());
    client.shutdown().await.unwrap();

    let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("relay task hung")
        .unwrap()
        .unwrap();
    assert_eq!(up.load(Ordering::Relaxed), stats.client_to_proxy);
    assert_eq!(down.load(Ordering::Relaxed), stats.proxy_to_client);
    assert_eq!(accepted.0.load(Ordering::Relaxed), stats.client_to_proxy);
    assert_eq!(accepted.1.load(Ordering::Relaxed), stats.proxy_to_client);
}

/// Pipe exhaustion happens before any byte moves: the connection copies
/// instead of failing, and later connections still try splice.
#[tokio::test]
async fn missing_pipes_fall_back_to_copy_without_latching() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    let echo = spawn_echo().await;
    test_hook::fail_pipes();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = listener.local_addr().unwrap();
    let (progress, accepted) = observed_progress();
    let relay = tokio::spawn(async move {
        let (mut client, client_addr) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(echo).await.unwrap();
        relay_splice(&mut client, upstream, client_addr, echo, Some(progress)).await
    });

    let mut client = TcpStream::connect(front).await.unwrap();
    let payload = pattern(96 * 1024);
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut echoed))
        .await
        .expect("pipe fallback hung")
        .unwrap();
    assert!(echoed == payload);
    let stats = relay.await.unwrap().unwrap();
    assert_eq!(stats.client_to_proxy, payload.len() as u64);
    assert_eq!(stats.proxy_to_client, payload.len() as u64);
    assert_eq!(accepted.0.load(Ordering::Relaxed), payload.len() as u64);
    assert_eq!(test_hook::probe_calls(), 0);
    assert!(splice_available());
}

/// A probe that fails with an unsupported errno must fall back to the
/// copy relay without losing a single byte, latch the global flag, and
/// skip probing for the next connection.
#[tokio::test]
async fn test_probe_failure_falls_back_to_copy() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();

    let echo = spawn_echo().await;

    // Arm the probe hook: the first connection's probes fail with EINVAL.
    test_hook::set_forced_errno(libc::EINVAL, -1);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = listener.local_addr().unwrap();
    let (progress, accepted) = observed_progress();
    let relay = tokio::spawn(async move {
        let (mut client, client_addr) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(echo).await.unwrap();
        relay_splice(&mut client, upstream, client_addr, echo, Some(progress))
            .await
            .unwrap()
    });

    let mut client = TcpStream::connect(front).await.unwrap();
    let payload = b"fallback keeps every byte";
    client.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_exact(&mut buf),
    )
    .await
    .expect("fallback copy hung")
    .unwrap();
    assert_eq!(&buf, payload);
    // The failed probe latched the process-wide flag.
    assert!(!splice_available());
    assert_eq!(accepted.0.load(Ordering::Relaxed), payload.len() as u64);
    assert_eq!(accepted.1.load(Ordering::Relaxed), payload.len() as u64);
    assert!(!relay.is_finished());
    client.shutdown().await.unwrap();

    let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
        .await
        .expect("relay task hung")
        .unwrap();
    assert_eq!(stats.client_to_proxy, payload.len() as u64);
    assert_eq!(stats.proxy_to_client, payload.len() as u64);
    assert_eq!(accepted.0.load(Ordering::Relaxed), stats.client_to_proxy);
    assert_eq!(accepted.1.load(Ordering::Relaxed), stats.proxy_to_client);

    // Second connection: the latched flag skips the probe entirely and
    // goes straight to the copy relay (hook still armed).
    let probes_before = test_hook::probe_calls();
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front2 = listener2.local_addr().unwrap();
    let (progress, accepted) = observed_progress();
    let relay2 = tokio::spawn(async move {
        let (mut client, client_addr) = listener2.accept().await.unwrap();
        let upstream = TcpStream::connect(echo).await.unwrap();
        relay_splice(&mut client, upstream, client_addr, echo, Some(progress))
            .await
            .unwrap()
    });
    let mut client2 = TcpStream::connect(front2).await.unwrap();
    client2.write_all(payload).await.unwrap();
    let mut buf2 = vec![0u8; payload.len()];
    client2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, payload);
    assert_eq!(accepted.0.load(Ordering::Relaxed), payload.len() as u64);
    assert_eq!(accepted.1.load(Ordering::Relaxed), payload.len() as u64);
    client2.shutdown().await.unwrap();
    let stats2 = tokio::time::timeout(std::time::Duration::from_secs(5), relay2)
        .await
        .expect("relay task hung")
        .unwrap();
    assert_eq!(stats2.total_bytes, 2 * payload.len() as u64);
    assert_eq!(accepted.0.load(Ordering::Relaxed), stats2.client_to_proxy);
    assert_eq!(accepted.1.load(Ordering::Relaxed), stats2.proxy_to_client);
    assert_eq!(
        test_hook::probe_calls(),
        probes_before,
        "probe must be skipped once splice is known unsupported"
    );
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept(),
    );
    (client.unwrap(), server.unwrap().0)
}

#[tokio::test]
async fn splice_probe_reset_preserves_origin_and_errno() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        for client_reset in [true, false] {
            let (client_peer, mut client) = tcp_pair().await;
            let (upstream_peer, upstream) = tcp_pair().await;
            let client_addr = client.peer_addr().unwrap();
            let target_addr = upstream.peer_addr().unwrap();
            let reset = if client_reset {
                client_peer
            } else {
                upstream_peer
            };
            socket2::SockRef::from(&reset)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(reset);
            let reset_socket = if client_reset { &client } else { &upstream };
            reset_socket.readable().await.unwrap();
            let (progress, accepted) = observed_progress();
            let error = relay_splice(
                &mut client,
                upstream,
                client_addr,
                target_addr,
                Some(progress.clone()),
            )
            .await
            .unwrap_err();
            assert_eq!(error.is::<crate::relay::ClientIoError>(), client_reset);
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(libc::ECONNRESET)
            );
            assert_eq!(progress.upload.load(Ordering::Relaxed), 0);
            assert_eq!(progress.download.load(Ordering::Relaxed), 0);
            assert_eq!(accepted.0.load(Ordering::Relaxed), 0);
            assert_eq!(accepted.1.load(Ordering::Relaxed), 0);
            assert!(splice_available());
        }
        let (mut sender, mut client) = tcp_pair().await;
        let (mut receiver, upstream) = tcp_pair().await;
        sender.write_all(b"staged").await.unwrap();
        client.readable().await.unwrap();
        test_hook::set_forced_errno(libc::EINVAL, upstream.as_raw_fd());
        let client_addr = client.peer_addr().unwrap();
        let target_addr = upstream.peer_addr().unwrap();
        let (progress, accepted) = observed_progress();
        let error = relay_splice(
            &mut client,
            upstream,
            client_addr,
            target_addr,
            Some(progress.clone()),
        )
        .await
        .unwrap_err();
        assert!(!error.is::<crate::relay::ClientIoError>());
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Other
        );
        assert!(splice_available());
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
        assert_eq!(progress.upload.load(Ordering::Relaxed), 0);
        assert_eq!(progress.download.load(Ordering::Relaxed), 0);
        assert_eq!(accepted.0.load(Ordering::Relaxed), 0);
        assert_eq!(accepted.1.load(Ordering::Relaxed), 0);
    })
    .await
    .expect("splice probe reset did not complete");
}

#[tokio::test]
async fn splice_source_reset_preserves_origin_after_accepted_bytes() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        for upload in [true, false] {
            let (mut sender, source) = tcp_pair().await;
            let (destination, mut receiver) = tcp_pair().await;
            let pipe = Pipe::new().unwrap();
            let (progress, accepted) = observed_progress();
            let exchange = async {
                sender.write_all(b"accepted").await.unwrap();
                let mut received = [0; 8];
                receiver.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, b"accepted");
                socket2::SockRef::from(&sender)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
                drop(sender);
            };
            let (result, ()) = tokio::join!(
                pump(&source, &destination, &pipe, 0, &progress, upload),
                exchange,
            );
            let error = result.unwrap_err().into_anyhow();
            assert_eq!(error.is::<crate::relay::ClientIoError>(), upload);
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(libc::ECONNRESET)
            );
            let expected = if upload { (8, 0) } else { (0, 8) };
            assert_eq!(progress.upload.load(Ordering::Relaxed), expected.0);
            assert_eq!(progress.download.load(Ordering::Relaxed), expected.1);
            assert_eq!(accepted.0.load(Ordering::Relaxed), expected.0);
            assert_eq!(accepted.1.load(Ordering::Relaxed), expected.1);
        }
    })
    .await
    .expect("splice source reset did not complete");
}

#[tokio::test]
async fn splice_first_response_precedes_blocked_client_for_staged_and_new_bytes() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        for initially_staged in [false, true] {
            let (mut server, source) = tcp_pair().await;
            let (destination, mut client) = tcp_pair().await;
            socket2::SockRef::from(&destination)
                .set_send_buffer_size(4096)
                .unwrap();
            socket2::SockRef::from(&client)
                .set_recv_buffer_size(4096)
                .unwrap();
            let mut filler = 0;
            while let Ok(ready) =
                tokio::time::timeout(Duration::from_millis(100), destination.writable()).await
            {
                ready.unwrap();
                match destination.try_write(&[0; 4096]) {
                    Ok(n) => filler += n,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("filling client buffer: {error}"),
                }
            }
            server.write_all(b"reply").await.unwrap();
            source.readable().await.unwrap();
            let pipe = Pipe::new().unwrap();
            let staged = if initially_staged {
                let staged = probe(&source, &pipe, false).unwrap();
                assert_eq!(staged, 5);
                staged
            } else {
                0
            };
            let (mut progress, accepted) = observed_progress();
            let responses = Arc::new(AtomicUsize::new(0));
            let response_ready = Arc::new(tokio::sync::Notify::new());
            progress.first_response = Some(Arc::new({
                let responses = responses.clone();
                let response_ready = response_ready.clone();
                move || {
                    responses.fetch_add(1, Ordering::Relaxed);
                    response_ready.notify_one();
                }
            }));
            let transfer = pump(&source, &destination, &pipe, staged, &progress, false);
            tokio::pin!(transfer);
            tokio::select! {
                result = &mut transfer => panic!("blocked transfer completed: {result:?}"),
                _ = response_ready.notified() => {}
            }
            assert_eq!(responses.load(Ordering::Relaxed), 1);
            assert_eq!(accepted.1.load(Ordering::Relaxed), 0);
            let exchange = async {
                let mut initial = vec![0; filler];
                client.read_exact(&mut initial).await.unwrap();
                server.write_all(b"again").await.unwrap();
                server.shutdown().await.unwrap();
                let mut received = Vec::new();
                client.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"replyagain");
            };
            let (total, ()) = tokio::join!(&mut transfer, exchange);
            assert_eq!(total.unwrap(), 10);
            assert_eq!(accepted.0.load(Ordering::Relaxed), 0);
            assert_eq!(accepted.1.load(Ordering::Relaxed), 10);
            assert_eq!(responses.load(Ordering::Relaxed), 1);
        }
    })
    .await
    .expect("splice response observation waited for client writes or EOF");
}

#[tokio::test]
async fn splice_transfer_counts_only_accepted_partial_writes_before_error() {
    let _lock = TEST_LOCK.lock().await;
    let _state = StateGuard::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        for upload in [true, false] {
            let (_server, source) = tcp_pair().await;
            let (destination, mut client) = tcp_pair().await;
            let pipe = Pipe::new().unwrap();
            assert_eq!(nix::unistd::write(&pipe.write, b"abcdefgh").unwrap(), 8);
            let (progress, accepted) = observed_progress();
            test_hook::fail_write_after(destination.as_raw_fd(), 5);
            let error = pump(&source, &destination, &pipe, 8, &progress, upload)
                .await
                .unwrap_err()
                .into_anyhow();
            assert_eq!(error.is::<crate::relay::ClientIoError>(), !upload);
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(libc::EPIPE)
            );
            test_hook::fail_write_after(-1, -1);
            drop(destination);
            let mut received = Vec::new();
            client.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"abcde");
            let expected = if upload { (5, 0) } else { (0, 5) };
            assert_eq!(progress.upload.load(Ordering::Relaxed), expected.0);
            assert_eq!(progress.download.load(Ordering::Relaxed), expected.1);
            assert_eq!(accepted.0.load(Ordering::Relaxed), expected.0);
            assert_eq!(accepted.1.load(Ordering::Relaxed), expected.1);
        }
    })
    .await
    .expect("splice partial-write failure did not complete");
}
