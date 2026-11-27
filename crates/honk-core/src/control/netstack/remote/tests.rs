use super::*;
use honk_netstack::{AcceptOpts, Config, ExcludeSet, Mode, Rx};
use std::task::Wake;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn transfer(sender: &mut Stack, receiver: &mut Stack, now: Instant) {
    let mut packet = [0; 1500];
    let length = sender.poll_transmit(now, &mut packet).expect("TCP output");
    assert_eq!(receiver.receive(now, &packet[..length]), Rx::Consumed);
}

fn connected(now: Instant) -> ((Stack, FlowId), (Stack, FlowId)) {
    let mut client = Config::new([1; 32]);
    client.local_v4 = Some("192.0.2.1".parse().unwrap());
    let mut client = Stack::new(client, now);
    let mut server = Config::new([2; 32]);
    server.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    let mut server = Stack::new(server, now);
    let (id, client_id) = handshake(&mut client, &mut server, now);
    ((server, id), (client, client_id))
}

fn handshake(client: &mut Stack, server: &mut Stack, now: Instant) -> (FlowId, FlowId) {
    let client_id = client
        .tcp_connect(now, "198.51.100.9:443".parse().unwrap())
        .unwrap();
    transfer(client, server, now);
    let id = server.poll_accept().unwrap().id;
    server.tcp_accept(id, AcceptOpts::default()).unwrap();
    transfer(server, client, now);
    transfer(client, server, now);
    (id, client_id)
}

#[tokio::test]
async fn partial_stack_commit_fences_flush_progress_and_fin() {
    check_partial_stack_commit(false).await;
    check_partial_stack_commit(true).await;
}

async fn check_partial_stack_commit(split: bool) {
    let now = Instant::now();
    let ((mut server, id), (mut client, client_id)) = connected(now);
    let budget = MemoryBudget::new(128 << 10);
    let wakes = Arc::new(Wakes::default());
    let (mut owner, mut app) = pair(
        id,
        &budget,
        &RemoteChunkPool::new(&budget, 1).unwrap(),
        wakes.clone().into(),
        Arc::new(0.into()),
        None,
    )
    .unwrap();
    let progress = app.progress();
    let empty = budget.used();
    let mut write_half;
    let tx: &mut (dyn AsyncWrite + Unpin) = if split {
        let (_, writer) = app.split_mut();
        write_half = writer;
        &mut write_half
    } else {
        &mut app
    };
    assert_eq!(tx.write(b"abcdef").await.unwrap(), 6);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert_eq!(progress.snapshot(), (0, None, None));
    assert!(futures::poll!(std::pin::pin!(tx.flush())).is_pending());
    assert_eq!(owner.pump_tx(&mut server, 2, now).unwrap(), 2);
    assert_eq!(progress.snapshot().0, 2);
    assert!(futures::poll!(std::pin::pin!(tx.shutdown())).is_pending());
    assert!(!owner.shutdown_pending());
    assert!(futures::poll!(std::pin::pin!(tx.flush())).is_pending());
    assert_eq!(owner.pump_tx(&mut server, SMALL_CHUNK, now).unwrap(), 4);
    assert_eq!(budget.used(), empty);
    tx.flush().await.unwrap();
    assert!(owner.shutdown_pending());
    owner.finish_shutdown(server.tcp_shutdown(id));
    tx.shutdown().await.unwrap();
    assert!(progress.finished());
    let (total, first, last) = progress.snapshot();
    assert_eq!(total, 6);
    assert!(last.unwrap() >= first.unwrap());
    transfer(&mut server, &mut client, now);
    let mut reply = [0; 6];
    assert_eq!(client.tcp_read(client_id, &mut reply).unwrap(), reply.len());
    assert_eq!(&reply, b"abcdef");
    drop((owner, app, progress));
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn full_rings_return_credit_and_deliver_buffered_data_before_reset() {
    let ((_, id), _) = connected(Instant::now());
    // Budget fits both full bulk rings while staying above the 75% recycle threshold so
    // consuming under pressure refunds immediately.
    let ring_bytes = BULK_CHUNK * SLOTS;
    let budget = MemoryBudget::new(ring_bytes * 2 + (32 << 10));
    let wakes = Arc::new(Wakes::default());
    let pressure = Arc::new(AtomicU64::new(0));
    let (mut owner, mut app) = pair(
        id,
        &budget,
        &RemoteChunkPool::new(&budget, 1).unwrap(),
        wakes.clone().into(),
        pressure.clone(),
        None,
    )
    .unwrap();
    let empty = budget.used();
    let bytes: Vec<_> = (0..=ring_bytes).map(|i| i as u8).collect();
    let (a, b) = bytes.split_at(17);
    assert_eq!(
        owner.push_rx(&[IoSlice::new(a), IoSlice::new(b)]),
        ring_bytes
    );
    assert_eq!(app.write(&bytes).await.unwrap(), ring_bytes);
    assert!(futures::poll!(std::pin::pin!(app.write(&[9]))).is_pending());
    assert_eq!(pressure.load(Ordering::Relaxed), 3);
    let full = budget.used();
    let mut first = [0; 1];
    app.read_exact(&mut first).await.unwrap();
    assert_eq!(first[0], bytes[0]);
    assert_eq!(budget.used(), full);
    assert_eq!(owner.push_rx(&[IoSlice::new(b"x")]), 0);
    let mut tail = vec![0; BULK_CHUNK - 1];
    app.read_exact(&mut tail).await.unwrap();
    assert_eq!(tail, bytes[1..BULK_CHUNK]);
    assert!(budget.used() < full);
    // Quarter-ring hysteresis defers owner wake until occupancy reaches WAKE_LOW_WATERMARK.
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    let mut drained_prefix = vec![0; BULK_CHUNK * (SLOTS - WAKE_LOW_WATERMARK - 1)];
    app.read_exact(&mut drained_prefix).await.unwrap();
    assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
    assert_eq!(owner.push_rx(&[IoSlice::new(b"x")]), 1);
    owner.fail(StreamError::Reset);
    let err = app.flush().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    let mut drained = Vec::new();
    assert_eq!(
        app.read_to_end(&mut drained).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    let consumed = BULK_CHUNK * (SLOTS - WAKE_LOW_WATERMARK);
    assert_eq!(drained[..drained.len() - 1], bytes[consumed..ring_bytes]);
    assert_eq!(drained.last(), Some(&b'x'));
    assert!(app.progress().finished());
    assert_eq!(app.progress().snapshot().0, 0);
    assert!(budget.used() >= empty);
    drop((owner, app));
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn shared_budget_refund_rearms_writer_and_eof_preserves_payload() {
    let ((_, id), _) = connected(Instant::now());
    let budget = MemoryBudget::new(32 << 10);
    let owner_wake = Arc::new(Wakes::default());
    let (mut owner, mut app) = pair(
        id,
        &budget,
        &RemoteChunkPool::new(&budget, 1).unwrap(),
        owner_wake.clone().into(),
        Arc::new(0.into()),
        None,
    )
    .unwrap();
    let other_flow = budget.reserve(budget.limit() - budget.used()).unwrap();
    let task_wake = Arc::new(Wakes::default());
    let waker = Waker::from(task_wake.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(
        Pin::new(&mut app)
            .poll_write(&mut cx, b"staged")
            .is_pending()
    );
    assert!(owner.budget_blocked());
    assert_eq!(owner_wake.0.load(Ordering::Relaxed), 1);
    drop(other_flow);
    owner.retry_budget();
    assert_eq!(task_wake.0.load(Ordering::Relaxed), 1);
    app.write_all(b"staged").await.unwrap();
    assert_eq!(owner.push_rx(&[IoSlice::new(b"last")]), 4);
    owner.finish_rx(None);
    drop(owner);
    let mut data = Vec::new();
    assert_eq!(app.read_to_end(&mut data).await.unwrap(), 4);
    assert_eq!(data, b"last");
    assert!(app.flush().await.is_err());
    assert_eq!(app.progress().snapshot().0, 0);
    drop(app);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn reader_and_owner_wake_across_multiple_ring_wraps() {
    let ((_, id), _) = connected(Instant::now());
    let bytes: Vec<_> = (0..4 * BULK_CHUNK * SLOTS)
        .map(|i| (i ^ (i / BULK_CHUNK)) as u8)
        .collect();
    let budget = MemoryBudget::new(2048 << 10);
    let wake = Arc::new(AtomicWaker::new());
    let owner_wake = waker_fn(wake.clone());
    let (mut owner, mut app) = pair(
        id,
        &budget,
        &RemoteChunkPool::new(&budget, 1).unwrap(),
        owner_wake,
        Arc::new(AtomicU64::new(0)),
        None,
    )
    .unwrap();
    let expected = bytes.clone();
    let producer = std::thread::spawn(move || {
        futures::executor::block_on(async {
            let mut offset = 0;
            while offset < bytes.len() {
                offset += std::future::poll_fn(|cx| {
                    wake.register(cx.waker());
                    let n = owner.push_rx(&[IoSlice::new(&bytes[offset..])]);
                    if n == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(n)
                    }
                })
                .await;
            }
            owner.finish_rx(None);
        });
    });
    let mut received = Vec::new();
    app.read_to_end(&mut received).await.unwrap();
    producer.join().unwrap();
    assert_eq!(received, expected);
    drop(app);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn bulk_recycle_and_direct_progress_throttle_wakeups() {
    let now = Instant::now();
    let ((mut server, id), _) = connected(now);
    let budget = MemoryBudget::new(4 << 20);
    let owner_wake = Arc::new(Wakes::default());
    let download = Arc::new(AtomicU64::new(0));
    let outbound = Arc::new(crate::stats::OutboundTracker::new());

    // 1. Unobserved direct counters: zero progress wakeups until finish.
    let (mut owner, mut app) = pair(
        id,
        &budget,
        &RemoteChunkPool::new(&budget, 1).unwrap(),
        owner_wake.clone().into(),
        Arc::new(0.into()),
        Some(RemoteCounters {
            download: Arc::clone(&download),
            outbound: Some(Arc::clone(&outbound)),
            observe_live: false,
        }),
    )
    .unwrap();
    let progress = app.progress();
    let progress_wakes = Arc::new(Wakes::default());
    let progress_waker = Waker::from(Arc::clone(&progress_wakes));
    let mut pcx = Context::from_waker(&progress_waker);
    assert!(progress.poll_finished(&mut pcx).is_pending());
    let payload = vec![0x5a; BULK_CHUNK * 2];
    assert_eq!(app.write(&payload).await.unwrap(), payload.len());
    let pumped = owner.pump_tx(&mut server, payload.len(), now).unwrap();
    assert!(pumped > 0);
    assert_eq!(download.load(Ordering::Relaxed), pumped as u64);
    assert_eq!(outbound.rx_bytes.load(Ordering::Relaxed), pumped as u64);
    assert_eq!(progress.accepted(), pumped as u64);
    assert_eq!(progress_wakes.0.load(Ordering::Relaxed), 0);
    let steady = budget.used();
    // Steady-state bulk recycling keeps budget usage flat across repeated writes/reads.
    assert_eq!(app.write(&payload[..BULK_CHUNK]).await.unwrap(), BULK_CHUNK);
    assert_eq!(budget.used(), steady);
    owner.fail(StreamError::Reset);
    assert_eq!(progress_wakes.0.load(Ordering::Relaxed), 1);
    assert!(progress.poll_finished(&mut pcx).is_ready());
    drop((owner, app, progress));
    assert_eq!(budget.used(), 0);

    // 2. Live-observed counters (Score): wake on first byte and every 100ms, not per batch.
    let ((mut server, id), _) = connected(now);
    let (mut owner, mut app) = pair(
        id,
        &budget,
        &RemoteChunkPool::new(&budget, 1).unwrap(),
        owner_wake.into(),
        Arc::new(0.into()),
        Some(RemoteCounters {
            download: Arc::new(AtomicU64::new(0)),
            outbound: None,
            observe_live: true,
        }),
    )
    .unwrap();
    let progress = app.progress();
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    assert!(progress.poll_changed(&mut cx, 0).is_pending());
    assert_eq!(app.write(&[1; 16]).await.unwrap(), 16);
    assert_eq!(owner.pump_tx(&mut server, 4, now).unwrap(), 4);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert!(progress.poll_changed(&mut cx, 4).is_pending());
    assert_eq!(
        owner
            .pump_tx(&mut server, 4, now + Duration::from_millis(50))
            .unwrap(),
        4
    );
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert_eq!(
        owner
            .pump_tx(&mut server, 4, now + PROGRESS_REPORT_INTERVAL)
            .unwrap(),
        4
    );
    assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
    drop((owner, app, progress));
    assert_eq!(budget.used(), 0);
}

fn waker_fn(wake: Arc<AtomicWaker>) -> Waker {
    struct Signal(Arc<AtomicWaker>);
    impl Wake for Signal {
        fn wake(self: Arc<Self>) {
            self.0.wake();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.wake();
        }
    }
    Waker::from(Arc::new(Signal(wake)))
}

mod buffered;
mod pool;
