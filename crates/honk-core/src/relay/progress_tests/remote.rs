use super::*;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::{BufReader, BufWriter};
use tokio::time::{Instant, sleep_until, timeout};

const ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80));
const REQUEST: &[u8] = b"request";
const TIMER_MARGIN: Duration = Duration::from_millis(10);

fn progress() -> RelayProgress {
    RelayProgress {
        upload: Arc::default(),
        download: Arc::default(),
        outbound: None,
        first_response: None,
        on_transfer: None,
    }
}

#[tokio::test(start_paused = true)]
async fn pending_upload_flushes_buffered_writer_before_client_eof() {
    let (mut client, client_rd) = tokio::io::duplex(64);
    let (mut proxy, mut peer) = tokio::io::duplex(1);
    proxy.write_u8(b'!').await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    let progress = progress();
    let mut relay = std::pin::pin!(relay_remote_tcp(
        (BufReader::new(client_rd), tokio::io::sink()),
        BufWriter::with_capacity(16, proxy),
        (ADDR, ADDR),
        &progress,
        || 0,
    ));

    assert!(futures::poll!(relay.as_mut()).is_pending());
    assert_eq!(
        progress.upload.load(Ordering::Relaxed),
        REQUEST.len() as u64
    );
    // The underlying pipe was full on the first attempted flush.
    assert_eq!(peer.read_u8().now_or_never().unwrap().unwrap(), b'!');
    let mut received = [0; REQUEST.len()];
    timeout(DRAIN_DEADLINE / 4, async {
        tokio::select! {
            result = relay.as_mut() => {
                panic!("relay ended with the upload source open: {result:?}");
            }
            result = peer.read_exact(&mut received) => { result.unwrap(); }
        }
    })
    .await
    .expect("the buffered upload did not flush while the source was pending");
    assert_eq!(received.as_slice(), REQUEST);

    client.shutdown().await.unwrap();
    peer.shutdown().await.unwrap();
    timeout(DRAIN_DEADLINE / 4, relay).await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn retained_upload_peeks_renew_drain_only_on_first_observation() {
    let (mut client, client_rd) = tokio::io::duplex(64);
    let (mut proxy, mut peer) = tokio::io::duplex(1);
    proxy.write_u8(b'!').await.unwrap();
    peer.shutdown().await.unwrap();
    let progress = progress();
    let mut relay = std::pin::pin!(relay_remote_tcp(
        (BufReader::new(client_rd), tokio::io::sink()),
        proxy,
        (ADDR, ADDR),
        &progress,
        || 0,
    ));

    let start = Instant::now();
    assert!(futures::poll!(relay.as_mut()).is_pending());
    sleep_until(start + DRAIN_DEADLINE / 2).await;
    let peek_at = Instant::now();
    client.write_all(REQUEST).await.unwrap();
    assert!(futures::poll!(relay.as_mut()).is_pending());
    assert_eq!(progress.upload.load(Ordering::Relaxed), 0);

    sleep_until(start + DRAIN_DEADLINE + TIMER_MARGIN).await;
    assert!(
        futures::poll!(relay.as_mut()).is_pending(),
        "the first peek of new data did not extend the deadline"
    );
    let renewed = peek_at + DRAIN_DEADLINE;
    sleep_until(renewed - TIMER_MARGIN).await;
    assert!(futures::poll!(relay.as_mut()).is_pending());
    sleep_until(renewed + TIMER_MARGIN).await;
    let error = relay
        .as_mut()
        .now_or_never()
        .expect("repeated peeks extended the renewed deadline")
        .unwrap_err();
    assert!(error.is::<DrainExpired>(), "{error:?}");
    assert_eq!(progress.upload.load(Ordering::Relaxed), 0);
    assert_eq!(peer.read_u8().now_or_never().unwrap().unwrap(), b'!');
    assert_eq!(peer.read(&mut [0]).now_or_never().unwrap().unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn remote_upload_eof_bounds_a_pending_final_flush() {
    let (mut proxy, _peer) = tokio::io::duplex(1);
    proxy.write_u8(b'!').await.unwrap();
    let progress = progress();
    let mut relay = std::pin::pin!(relay_remote_tcp(
        (REQUEST, tokio::io::sink()),
        BufWriter::with_capacity(16, proxy),
        (ADDR, ADDR),
        &progress,
        || 0,
    ));

    let start = Instant::now();
    assert!(futures::poll!(relay.as_mut()).is_pending());
    assert_eq!(
        progress.upload.load(Ordering::Relaxed),
        REQUEST.len() as u64
    );
    sleep_until(start + DRAIN_DEADLINE - TIMER_MARGIN).await;
    assert!(futures::poll!(relay.as_mut()).is_pending());
    sleep_until(start + DRAIN_DEADLINE + TIMER_MARGIN).await;
    let error = relay
        .as_mut()
        .now_or_never()
        .expect("a blocked final flush prevented the drain from starting")
        .unwrap_err();
    assert!(error.is::<DrainExpired>(), "{error:?}");
}

#[tokio::test]
async fn upload_retries_short_writes_without_consuming_pending_bytes() {
    let mut rd = REQUEST;
    let (mut wr, mut peer) = tokio::io::duplex(2);
    let progress = CopyProgress::default();
    let eof = tokio::sync::Notify::new();
    let mut writes = Vec::new();
    let mut received = [0; REQUEST.len()];
    {
        let mut copy = std::pin::pin!(copy_buf_way(&mut rd, &mut wr, &progress, &eof, |n| {
            writes.push(n);
        }));
        for (index, chunk) in received.chunks_mut(2).enumerate() {
            let accepted = index * 2 + chunk.len();
            let result = futures::poll!(copy.as_mut());
            if accepted < REQUEST.len() {
                assert!(result.is_pending());
            } else {
                assert!(matches!(result, Poll::Ready(Ok(()))), "{result:?}");
            }
            assert_eq!(progress.snapshot(), (REQUEST.len() as u64, accepted as u64));
            peer.read_exact(chunk)
                .now_or_never()
                .expect("accepted bytes did not reach the peer")
                .unwrap();
        }
    }
    assert_eq!(received.as_slice(), REQUEST);
    assert!(rd.is_empty());
    assert_eq!(writes, [2, 2, 2, 1]);
    assert!(eof.notified().now_or_never().is_some());
    assert_eq!(peer.read(&mut [0]).now_or_never().unwrap().unwrap(), 0);
}

#[tokio::test]
async fn ready_upload_yields_before_exhausting_the_source() {
    tokio::spawn(async {
        let bytes = [b'x'; 4096];
        let mut rd = BufReader::with_capacity(1, bytes.as_slice());
        let mut wr = Vec::with_capacity(bytes.len());
        let progress = CopyProgress::default();
        let eof = tokio::sync::Notify::new();
        let mut copy = std::pin::pin!(copy_buf_way(&mut rd, &mut wr, &progress, &eof, |_| {}));
        assert!(futures::poll!(copy.as_mut()).is_pending());
        assert!((1..bytes.len() as u64).contains(&progress.snapshot().1));
        copy.await.unwrap();
        assert_eq!(
            progress.snapshot(),
            (bytes.len() as u64, bytes.len() as u64)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn remote_upload_preserves_error_side_and_polls_both_terminal_shutdowns() {
    use FailurePoint::{PendingFlush, Read, Write};

    for (point, zero_write) in [
        (Read, false),
        (Write, false),
        (Write, true),
        (PendingFlush, false),
    ] {
        let reset = || io::Error::from_raw_os_error(libc::ECONNRESET);
        let (mut client, client_rd) = tokio::io::duplex(64);
        let (mut client_wr, mut app) = tokio::io::duplex(64);
        let (proxy, mut peer) = tokio::io::duplex(64);
        let client_error = point == Read;
        let accepted = if point == Write { 3 } else { REQUEST.len() };
        let mut client_rd = BufReader::new(FailAfter {
            inner: client_rd,
            remaining: REQUEST.len(),
            point: if client_error { Read } else { Write },
            error: client_error.then(reset),
        });
        let mut proxy = FailAfter {
            inner: proxy,
            remaining: accepted,
            point: if client_error { Write } else { point },
            error: (!client_error && !zero_write).then(reset),
        };
        client.write_all(REQUEST).await.unwrap();
        let progress = progress();
        let error = relay_remote_tcp(
            (&mut client_rd, &mut client_wr),
            &mut proxy,
            (ADDR, ADDR),
            &progress,
            || 0,
        )
        .now_or_never()
        .expect("relay error waited for the opposite direction")
        .unwrap_err();
        assert_eq!(error.is::<ClientIoError>(), client_error, "{point:?}");
        let cause = error.downcast_ref::<io::Error>().unwrap();
        if zero_write {
            assert_eq!(cause.kind(), ErrorKind::WriteZero);
        } else {
            assert_eq!(cause.raw_os_error(), Some(libc::ECONNRESET), "{point:?}");
        }
        assert_eq!(progress.upload.load(Ordering::Relaxed), accepted as u64);
        assert_eq!(client_rd.buffer(), &REQUEST[accepted..]);

        let mut received = Vec::new();
        peer.read_to_end(&mut received)
            .now_or_never()
            .expect("terminal proxy shutdown was not polled")
            .unwrap();
        assert_eq!(received, &REQUEST[..accepted]);
        assert_eq!(
            app.read(&mut [0])
                .now_or_never()
                .expect("terminal client shutdown was not polled")
                .unwrap(),
            0
        );
    }
}

#[tokio::test(start_paused = true)]
async fn remote_relay_joins_both_half_closes_and_reports_response_and_stats() {
    const FIRST: &[u8] = b"first";
    const TAIL: &[u8] = b"reply";

    for upload_first in [true, false] {
        let (mut client, client_rd) = tokio::io::duplex(64);
        let (mut client_wr, mut app) = tokio::io::duplex(1);
        let (proxy, mut peer) = tokio::io::duplex(64);
        client_wr.write_u8(b'!').await.unwrap();
        peer.write_all(FIRST).await.unwrap();
        let responses = Arc::<AtomicUsize>::default();
        let accepted = Arc::<(AtomicU64, AtomicU64)>::default();
        let outbound = Arc::new(crate::stats::OutboundTracker::new());
        let progress = RelayProgress {
            outbound: Some(outbound.clone()),
            first_response: Some(Arc::new({
                let responses = responses.clone();
                move || {
                    responses.fetch_add(1, Ordering::Relaxed);
                }
            })),
            on_transfer: Some(Arc::new({
                let accepted = accepted.clone();
                move |up, down| {
                    accepted.0.fetch_add(up, Ordering::Relaxed);
                    accepted.1.fetch_add(down, Ordering::Relaxed);
                }
            })),
            ..progress()
        };
        let mut relay = std::pin::pin!(relay_remote_tcp(
            (BufReader::new(client_rd), client_wr),
            proxy,
            (ADDR, ADDR),
            &progress,
            || 0,
        ));

        assert!(futures::poll!(relay.as_mut()).is_pending());
        assert_eq!(responses.load(Ordering::Relaxed), 1);
        assert_eq!(app.read_u8().now_or_never().unwrap().unwrap(), b'!');
        let (mut peer_rd, mut peer_wr) = tokio::io::split(peer);
        let exchange = async {
            let upload = async {
                client.write_all(REQUEST).await.unwrap();
                client.shutdown().await.unwrap();
                let mut request = Vec::new();
                peer_rd.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, REQUEST);
            };
            let download = async {
                let mut first = [0; FIRST.len()];
                app.read_exact(&mut first).await.unwrap();
                assert_eq!(first.as_slice(), FIRST);
                peer_wr.write_all(TAIL).await.unwrap();
                peer_wr.shutdown().await.unwrap();
                let mut tail = Vec::new();
                app.read_to_end(&mut tail).await.unwrap();
                assert_eq!(tail, TAIL);
            };
            if upload_first {
                upload.await;
                download.await;
            } else {
                download.await;
                upload.await;
            }
        };
        let (stats, ()) = timeout(DRAIN_DEADLINE / 2, async { tokio::join!(relay, exchange) })
            .await
            .expect("both directions did not finish after their source half-closed");
        let stats = stats.unwrap();
        let up = REQUEST.len() as u64;
        let down = (FIRST.len() + TAIL.len()) as u64;
        assert_eq!(stats.client_to_proxy, up);
        assert_eq!(stats.proxy_to_client, down);
        assert_eq!(stats.total_bytes, up + down);
        assert_eq!(progress.upload.load(Ordering::Relaxed), up);
        assert_eq!(outbound.tx_bytes.load(Ordering::Relaxed), up);
        assert_eq!(accepted.0.load(Ordering::Relaxed), up);
        assert_eq!(accepted.1.load(Ordering::Relaxed), 0);
        assert_eq!(progress.download.load(Ordering::Relaxed), 0);
        assert_eq!(outbound.rx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(responses.load(Ordering::Relaxed), 1);
    }
}
