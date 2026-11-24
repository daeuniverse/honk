use super::*;
use futures::FutureExt;
use std::future::{Future, pending};
use tokio::io::BufWriter;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep, sleep_until, timeout};

const WINDOW: Duration = splice::DRAIN_DEADLINE;
const DEADLINE_MARGIN: Duration = Duration::from_millis(10);
// Step past each 100 ms idle sample, including the timer's millisecond rounding.
const SAMPLE_STEP: Duration = Duration::from_millis(101);
const LAST: &[u8] = b"ok";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalOp {
    Flush,
    Shutdown,
}

struct FinalWriter<F> {
    inner: BufWriter<DuplexStream>,
    point: FinalOp,
    gate: Option<Pin<Box<F>>>,
}

impl<F: Future<Output = io::Result<()>>> FinalWriter<F> {
    fn new(inner: DuplexStream, point: FinalOp, gate: F) -> Self {
        Self {
            inner: BufWriter::with_capacity(64, inner),
            point,
            gate: Some(Box::pin(gate)),
        }
    }

    fn poll_gate(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(gate) = &mut self.gate else {
            return Poll::Ready(Ok(()));
        };
        let result = std::task::ready!(gate.as_mut().poll(cx));
        self.gate = None;
        Poll::Ready(result)
    }
}

impl<F> AsyncRead for FinalWriter<F> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.inner.get_mut()).poll_read(cx, buf)
    }
}

impl<F: Future<Output = io::Result<()>>> AsyncWrite for FinalWriter<F> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.point == FinalOp::Flush && !self.inner.buffer().is_empty() {
            std::task::ready!(self.poll_gate(cx))?;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.point {
            FinalOp::Flush => std::task::ready!(self.as_mut().poll_flush(cx))?,
            FinalOp::Shutdown => std::task::ready!(self.poll_gate(cx))?,
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn copy_to(
    source: impl AsyncRead + AsyncWrite + Send + Unpin,
    destination: impl AsyncRead + AsyncWrite + Send + Unpin,
    client_destination: bool,
) -> anyhow::Result<RelayStats> {
    let addr = "127.0.0.1:80".parse().unwrap();
    if client_destination {
        relay_tcp(destination, source, addr, addr).await
    } else {
        relay_tcp(source, destination, addr, addr).await
    }
}

// Keep polling the relay while time advances so each idle sample can run.
async fn assert_pending_for(
    relay: Pin<&mut impl Future<Output = anyhow::Result<RelayStats>>>,
    duration: Duration,
) {
    tokio::select! {
        biased;
        result = relay => panic!("relay ended before the observation window: {result:?}"),
        () = sleep(duration) => {}
    }
}

#[tokio::test(start_paused = true)]
async fn first_eof_bounds_final_flush_and_shutdown_in_both_directions() {
    const REVERSE: &[u8] = b"reply";
    const REVERSE_CAPACITY: usize = 3;

    for client_destination in [false, true] {
        for point in [FinalOp::Flush, FinalOp::Shutdown] {
            for released in [true, false] {
                let (mut sender, source) = tokio::io::duplex(REVERSE_CAPACITY);
                let (destination, mut receiver) = tokio::io::duplex(64);
                sender.write_all(LAST).await.unwrap();
                sender.shutdown().await.unwrap();
                if !released {
                    receiver.write_all(REVERSE).await.unwrap();
                }
                let (release, gate) = oneshot::channel();
                let destination = FinalWriter::new(destination, point, async {
                    gate.await.unwrap();
                    Ok(())
                });
                let start = Instant::now();
                let relay = copy_to(source, destination, client_destination);
                tokio::pin!(relay);
                assert_pending_for(relay.as_mut(), WINDOW / 2).await;

                let mut wire = Vec::new();
                if point == FinalOp::Shutdown {
                    let mut payload = [0; LAST.len()];
                    receiver
                        .read_exact(&mut payload)
                        .now_or_never()
                        .expect("shutdown blocked before final flush delivered the payload")
                        .unwrap();
                    wire.extend_from_slice(&payload);
                }
                assert!(
                    receiver.read_u8().now_or_never().is_none(),
                    "data or FIN escaped the {point:?} gate with client_destination={client_destination}"
                );

                if released {
                    release.send(()).unwrap();
                    assert!(futures::poll!(relay.as_mut()).is_pending());
                    receiver
                        .read_to_end(&mut wire)
                        .now_or_never()
                        .expect(
                            "released final operation did not send FIN while reverse read was open",
                        )
                        .unwrap();
                    receiver.shutdown().await.unwrap();
                }

                let stats = timeout(WINDOW, relay)
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{point:?} outlived the drain window with client_destination={client_destination}, released={released}")
                    })
                    .unwrap();
                let reverse_bytes = if released {
                    0
                } else {
                    assert!(start.elapsed() >= WINDOW);
                    receiver
                        .read_to_end(&mut wire)
                        .now_or_never()
                        .unwrap()
                        .unwrap();
                    let mut reverse = Vec::new();
                    sender
                        .read_to_end(&mut reverse)
                        .now_or_never()
                        .unwrap()
                        .unwrap();
                    assert_eq!(reverse, &REVERSE[..REVERSE_CAPACITY]);
                    REVERSE_CAPACITY as u64
                };
                let expected_wire = if released || point == FinalOp::Shutdown {
                    LAST
                } else {
                    b""
                };
                assert_eq!(wire, expected_wire);
                let forward_bytes = LAST.len() as u64;
                let expected = if client_destination {
                    (reverse_bytes, forward_bytes)
                } else {
                    (forward_bytes, reverse_bytes)
                };
                assert_eq!((stats.client_to_proxy, stats.proxy_to_client), expected);
            }
        }
    }
}

struct CopyCounters {
    progress: RelayProgress,
    accepted: Arc<(AtomicU64, AtomicU64)>,
}

impl CopyCounters {
    fn new((upload, download): (u64, u64)) -> Self {
        let accepted = Arc::new((AtomicU64::new(upload), AtomicU64::new(download)));
        let progress = RelayProgress {
            upload: Arc::new(AtomicU64::new(upload)),
            download: Arc::new(AtomicU64::new(download)),
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
        Self { progress, accepted }
    }

    fn assert_counts(&self, read: (u64, u64), written: (u64, u64)) {
        assert_eq!(
            (
                self.progress.upload.load(Ordering::Relaxed),
                self.progress.download.load(Ordering::Relaxed),
            ),
            read,
            "live source reads"
        );
        assert_eq!(
            (
                self.accepted.0.load(Ordering::Relaxed),
                self.accepted.1.load(Ordering::Relaxed),
            ),
            written,
            "accepted bytes reported by callbacks"
        );
    }
}

fn directional_counts(upload: bool, survivor: u64, reverse: u64) -> (u64, u64) {
    if upload {
        (survivor, reverse)
    } else {
        (reverse, survivor)
    }
}

#[tokio::test(start_paused = true)]
async fn idle_before_eof_stays_open_and_accepted_short_writes_renew_the_drain() {
    const PAYLOAD: &[u8] = b"active";
    for upload in [true, false] {
        let (mut receiver, destination) = tokio::io::duplex(1);
        let (source, mut sender) = tokio::io::duplex(64);
        let (client, proxy) = if upload {
            (source, destination)
        } else {
            (destination, source)
        };
        let addr = "127.0.0.1:80".parse().unwrap();
        let counters = CopyCounters::new((0, 0));
        receiver.write_u8(b'!').await.unwrap();
        let relay = splice::relay_auto(client, proxy, addr, addr, Some(counters.progress.clone()));
        tokio::pin!(relay);
        assert_pending_for(relay.as_mut(), WINDOW * 2).await;
        assert_eq!(sender.read_u8().now_or_never().unwrap().unwrap(), b'!');
        let before_eof = directional_counts(upload, 0, 1);
        counters.assert_counts(before_eof, before_eof);

        receiver.shutdown().await.unwrap();
        sender.write_all(PAYLOAD).await.unwrap();
        let full = directional_counts(upload, PAYLOAD.len() as u64, 1);
        // One source read, with each new accepted byte gated by the receiver reading.
        for (index, &byte) in PAYLOAD.iter().enumerate() {
            assert_pending_for(relay.as_mut(), WINDOW / 2).await;
            counters.assert_counts(full, directional_counts(upload, index as u64 + 1, 1));
            assert_eq!(receiver.read_u8().now_or_never().unwrap().unwrap(), byte);
        }
        sender.shutdown().await.unwrap();
        let stats = timeout(WINDOW / 2, relay).await.unwrap().unwrap();
        assert_eq!((stats.client_to_proxy, stats.proxy_to_client), full);
        counters.assert_counts(full, full);
        assert_eq!(receiver.read(&mut [0]).now_or_never().unwrap().unwrap(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn a_read_without_a_write_renews_once_and_the_cut_reports_only_accepted_bytes() {
    for (upload, read_delay) in [
        (true, WINDOW * 3 / 4),
        (false, WINDOW * 3 / 4),
        (true, WINDOW * 2),
        (false, WINDOW * 2),
    ] {
        let (mut receiver, destination) = tokio::io::duplex(3);
        let (source, mut sender) = tokio::io::duplex(64);
        let (client, proxy) = if upload {
            (source, destination)
        } else {
            (destination, source)
        };
        let addr = "127.0.0.1:80".parse().unwrap();
        let counters = CopyCounters::new(directional_counts(upload, 17, 0));
        sender.write_all(b"123").await.unwrap();
        let relay = splice::relay_auto(client, proxy, addr, addr, Some(counters.progress.clone()));
        tokio::pin!(relay);
        assert!(futures::poll!(relay.as_mut()).is_pending());
        let accepted = directional_counts(upload, 20, 0);
        counters.assert_counts(accepted, accepted);

        receiver.shutdown().await.unwrap();
        assert!(futures::poll!(relay.as_mut()).is_pending());
        // Hold the relay unpolled until fresh bytes arrive, even past the initial deadline.
        sleep(read_delay).await;
        let read_at = Instant::now();
        sender.write_all(b"45678").await.unwrap();
        assert!(futures::poll!(relay.as_mut()).is_pending());
        let live = directional_counts(upload, 25, 0);
        counters.assert_counts(live, accepted);
        sleep_until(read_at + WINDOW - DEADLINE_MARGIN).await;
        assert!(futures::poll!(relay.as_mut()).is_pending());

        sleep_until(read_at + WINDOW).await;
        let stats = relay
            .as_mut()
            .now_or_never()
            .expect("a blocked write extended the renewed deadline")
            .unwrap();
        assert_eq!(
            (stats.client_to_proxy, stats.proxy_to_client),
            directional_counts(upload, 3, 0)
        );
        counters.assert_counts(live, accepted);
        let mut wire = Vec::new();
        receiver
            .read_to_end(&mut wire)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(wire, b"123");
    }
}

#[tokio::test(start_paused = true)]
async fn lower_io_during_a_pending_final_flush_does_not_renew_the_drain() {
    let (mut sender, source) = tokio::io::duplex(8);
    let (destination, mut receiver) = tokio::io::duplex(8);
    let (mut carrier, mut lower) = tokio::io::duplex(8);
    sender.write_all(LAST).await.unwrap();
    sender.shutdown().await.unwrap();
    let received = AtomicUsize::new(0);
    let destination = FinalWriter::new(destination, FinalOp::Flush, async {
        let mut byte = [0; 1];
        while lower.read(&mut byte).await? != 0 {
            received.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });
    let start = Instant::now();
    let relay = copy_to(source, destination, false);
    tokio::pin!(relay);
    for n in 1..=3 {
        assert_pending_for(relay.as_mut(), WINDOW / 4).await;
        carrier.write_u8(n).await.unwrap();
        assert!(futures::poll!(relay.as_mut()).is_pending());
        assert_eq!(received.load(Ordering::Relaxed), usize::from(n));
    }

    let stats = timeout(WINDOW * 3 / 4, relay)
        .await
        .expect("lower I/O renewed the copy drain")
        .unwrap();
    assert!(start.elapsed() >= WINDOW);
    assert_eq!(
        (stats.client_to_proxy, stats.proxy_to_client),
        (LAST.len() as u64, 0)
    );
    assert_eq!(receiver.read(&mut [0]).now_or_never().unwrap().unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn pending_flush_cannot_starve_the_idle_timer_of_its_poll_budget() {
    let (mut sender, source) = tokio::io::duplex(8);
    let (destination, mut receiver) = tokio::io::duplex(8);
    sender.write_all(LAST).await.unwrap();
    sender.shutdown().await.unwrap();
    let (entered, mut started) = oneshot::channel();
    let destination = FinalWriter::new(destination, FinalOp::Flush, async move {
        entered.send(()).unwrap();
        loop {
            tokio::task::consume_budget().await;
        }
    });
    let (step, mut steps) = mpsc::unbounded_channel();
    let (report, mut reports) = mpsc::unbounded_channel();
    let driver = tokio::spawn(async move {
        let relay = copy_to(source, destination, false);
        tokio::pin!(relay);
        while steps.recv().await.is_some() {
            let result = futures::poll!(relay.as_mut());
            let finished = result.is_ready();
            report.send(result).unwrap();
            if finished {
                break;
            }
        }
    });

    let start = Instant::now();
    step.send(()).unwrap();
    assert!(reports.recv().await.unwrap().is_pending());
    started
        .try_recv()
        .expect("initial poll did not reach final flush");
    // Each permitted poll exhausts a fresh task budget, even when the flush wakes itself.
    let stats = loop {
        assert!(
            start.elapsed() < WINDOW * 2,
            "the pending flush starved the idle timer"
        );
        sleep(SAMPLE_STEP).await;
        step.send(()).unwrap();
        if let Poll::Ready(result) = reports.recv().await.unwrap() {
            break result.unwrap();
        }
    };
    driver.await.unwrap();
    assert!(start.elapsed() >= WINDOW);
    assert_eq!(
        (stats.client_to_proxy, stats.proxy_to_client),
        (LAST.len() as u64, 0)
    );
    assert_eq!(
        receiver
            .read_u8()
            .now_or_never()
            .unwrap()
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEof
    );
}

fn assert_reset(result: anyhow::Result<RelayStats>, client_side: bool) {
    let error = result.expect_err("relay hid a terminal connection reset");
    assert_eq!(error.is::<ClientIoError>(), client_side);
    let original = error.downcast_ref::<io::Error>().unwrap();
    assert_eq!(original.kind(), ErrorKind::ConnectionReset);
    assert_eq!(original.raw_os_error(), Some(libc::ECONNRESET));
}

#[tokio::test(start_paused = true)]
async fn final_flush_reset_ready_at_idle_expiry_keeps_its_errno_and_origin() {
    async fn relay_with_gated_reset(
        client_destination: bool,
        gate: oneshot::Receiver<()>,
    ) -> anyhow::Result<RelayStats> {
        let (mut sender, source) = tokio::io::duplex(8);
        let (destination, _receiver) = tokio::io::duplex(8);
        sender.write_all(LAST).await.unwrap();
        sender.shutdown().await.unwrap();
        let destination = FinalWriter::new(destination, FinalOp::Flush, async {
            gate.await.unwrap();
            Err(io::Error::from_raw_os_error(libc::ECONNRESET))
        });
        copy_to(source, destination, client_destination).await
    }

    for client_destination in [false, true] {
        let (_withheld_reset, silent_gate) = oneshot::channel();
        let (release_reset, reset_gate) = oneshot::channel();
        let silent = relay_with_gated_reset(client_destination, silent_gate);
        let reset = relay_with_gated_reset(client_destination, reset_gate);
        tokio::pin!(silent, reset);

        let start = Instant::now();
        assert!(silent.as_mut().now_or_never().is_none());
        assert!(reset.as_mut().now_or_never().is_none());
        sleep_until(start + WINDOW - DEADLINE_MARGIN).await;
        assert!(silent.as_mut().now_or_never().is_none());
        assert!(reset.as_mut().now_or_never().is_none());

        sleep_until(start + WINDOW).await;
        let control = silent
            .as_mut()
            .now_or_never()
            .expect("a delayed idle sample moved the first EOF deadline")
            .unwrap();
        assert_eq!(control.total_bytes, LAST.len() as u64);

        // Both the reset and the cutoff are ready at this same deadline.
        release_reset.send(()).unwrap();
        let result = reset
            .as_mut()
            .now_or_never()
            .expect("reset and cutoff are ready on this poll");
        assert_reset(result, client_destination);
    }
}

#[tokio::test(start_paused = true)]
async fn terminal_read_error_returns_without_waiting_on_cleanup_shutdown() {
    for client_side in [false, true] {
        let (fault, _sender) = tokio::io::duplex(8);
        let (destination, _receiver) = tokio::io::duplex(8);
        let fault = FailAfter {
            inner: fault,
            remaining: 0,
            point: FailurePoint::Read,
            error: Some(io::Error::from_raw_os_error(libc::ECONNRESET)),
        };
        let destination = FinalWriter::new(destination, FinalOp::Shutdown, pending());
        let result = timeout(WINDOW / 4, copy_to(fault, destination, !client_side))
            .await
            .expect("a terminal error waited for a new cleanup window");
        assert_reset(result, client_side);
    }
}
