use super::*;

fn attach(id: FlowId, pool: &Arc<RemoteChunkPool>) -> (RemoteOwner, RemoteEndpoint) {
    pair(
        id,
        &pool.budget,
        pool,
        Waker::noop().clone(),
        Arc::new(0.into()),
        None,
    )
    .unwrap()
}

async fn recycle_bulk(owner: &mut RemoteOwner, app: &mut RemoteEndpoint) {
    let bytes = [0x6b; BULK_CHUNK];
    assert_eq!(owner.push_rx(&[IoSlice::new(&bytes)]), bytes.len());
    let mut read = [0; BULK_CHUNK];
    app.read_exact(&mut read).await.unwrap();
    assert_eq!(read, bytes);
}

#[tokio::test]
async fn three_hundred_open_bulk_flows_refund_and_retry_without_closing() {
    let now = Instant::now();
    let ((mut server, first), (mut client, _)) = connected(now);
    let budget = MemoryBudget::new(1 << 20);
    let pool = RemoteChunkPool::new(&budget, 1).unwrap();
    let mut flows = vec![attach(first, &pool)];
    for _ in 1..300 {
        let (id, _) = handshake(&mut client, &mut server, now);
        flows.push(attach(id, &pool));
    }
    let live = budget.used();
    let payload = [0x37; BULK_CHUNK];
    let mut read = [0; BULK_CHUNK];
    for batch in flows.chunks_mut(pool.cap + 1) {
        for (owner, _) in &mut *batch {
            assert_eq!(owner.push_rx(&[IoSlice::new(&payload)]), payload.len());
        }
        for (_, app) in batch {
            app.read_exact(&mut read).await.unwrap();
            assert_eq!(read, payload);
        }
    }
    let bulk_charge = size_of::<Chunk>() + BULK_CHUNK;
    assert_eq!(budget.used(), live + pool.cap * bulk_charge);
    assert_eq!(pool.drains(), 0);
    pool.drain();
    assert_eq!(budget.used(), live);
    assert!(!pool.drain_if_cached());
    assert_eq!(pool.drains(), 1);

    let (owner, app) = &mut flows[0];
    recycle_bulk(owner, app).await;
    let busy = budget.reserve(budget.limit() - budget.used()).unwrap();
    let (owner, app) = &mut flows[299];
    // The small TX write needs a new grant while all 300 original pairs are live.
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(app).poll_write(&mut cx, b"!"),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(pool.drains(), 2);
    assert_eq!(owner.pump_tx(&mut server, 1, now).unwrap(), 1);
    drop(busy);
    assert_eq!(budget.used(), live);
    assert!(flows.iter().all(|(owner, _)| server.tcp_retained(owner.id)));
    drop((flows, pool));
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn shared_root_divides_bulk_capacity_across_all_pools() {
    let budget = MemoryBudget::new(4 << 20);
    let ((_, id), _) = connected(Instant::now());
    let pools: Vec<_> = (0..4)
        .map(|_| RemoteChunkPool::new(&budget, 4).unwrap())
        .collect();
    let metadata = ARC_HEADER + size_of::<RemoteChunkPool>() + 4 * size_of::<Box<Chunk>>();
    assert_eq!(budget.used(), 4 * metadata);
    for pool in &pools {
        assert_eq!(pool.cap, 4);
        let (mut owner, mut app) = attach(id, pool);
        let bytes = vec![1; 5 * BULK_CHUNK];
        assert_eq!(owner.push_rx(&[IoSlice::new(&bytes)]), bytes.len());
        let mut read = vec![0; bytes.len()];
        app.read_exact(&mut read).await.unwrap();
        assert_eq!(read, bytes);
    }
    assert_eq!(
        budget.used(),
        4 * metadata + 16 * (BULK_CHUNK + size_of::<Chunk>())
    );
    drop(pools);
    assert_eq!(budget.used(), 0);

    let tiny = RemoteChunkPool::new(&budget, usize::MAX).unwrap();
    assert_eq!(tiny.cap, 0);
    let (mut owner, mut app) = attach(id, &tiny);
    let baseline = budget.used();
    recycle_bulk(&mut owner, &mut app).await;
    assert_eq!(budget.used(), baseline);
    assert_eq!(
        RemoteChunkPool::new(&MemoryBudget::new(usize::MAX), 0)
            .unwrap()
            .cap,
        MAX_CACHED
    );
    assert!(RemoteChunkPool::new(&MemoryBudget::new(1), 1).is_err());
}

#[tokio::test]
async fn both_writers_refund_cached_bulk_synchronously_or_report_pressure() {
    let now = Instant::now();
    let ((mut server, seed), (mut client, _)) = connected(now);
    let (id, _) = handshake(&mut client, &mut server, now);
    let budget = MemoryBudget::new(1 << 20);
    let pool = RemoteChunkPool::new(&budget, 1).unwrap();
    let (mut producer, mut consumer) = attach(seed, &pool);
    let (mut owner, mut app) = attach(id, &pool);
    let baseline = budget.used();
    let mut cx = Context::from_waker(Waker::noop());
    for tx in [false, true] {
        recycle_bulk(&mut producer, &mut consumer).await;
        let other = budget.reserve(budget.limit() - budget.used()).unwrap();
        let before = pool.drains();
        if tx {
            assert!(matches!(
                Pin::new(&mut app).poll_write(&mut cx, b"t"),
                Poll::Ready(Ok(1))
            ));
            assert_eq!(owner.pump_tx(&mut server, 1, now).unwrap(), 1);
        } else {
            assert_eq!(owner.push_rx(&[IoSlice::new(b"r")]), 1);
            assert_eq!(app.read_u8().await.unwrap(), b'r');
        }
        assert_eq!(pool.drains(), before + 1);
        drop(other);
        assert_eq!(budget.used(), baseline);
    }
    let other = budget.reserve(budget.limit() - budget.used()).unwrap();
    let before = pool.drains();
    assert_eq!(owner.push_rx(&[IoSlice::new(b"r")]), 0);
    assert!(Pin::new(&mut app).poll_write(&mut cx, b"t").is_pending());
    assert_eq!(pool.drains(), before + 2);
    assert!(owner.budget_blocked());
    assert!(!owner.has_unread_rx() && !owner.tx_pending());
    drop(other);
    owner.retry_budget();
    assert_eq!(owner.push_rx(&[IoSlice::new(b"r")]), 1);
    assert!(matches!(
        Pin::new(&mut app).poll_write(&mut cx, b"t"),
        Poll::Ready(Ok(1))
    ));
}

#[tokio::test]
async fn either_pair_metadata_reservation_reclaims_idle_payload() {
    let now = Instant::now();
    let ((mut server, seed), (mut client, _)) = connected(now);
    let (id, _) = handshake(&mut client, &mut server, now);
    let budget = MemoryBudget::new(1 << 20);
    let pool = RemoteChunkPool::new(&budget, 1).unwrap();
    let (mut owner, mut app) = attach(seed, &pool);
    let baseline = budget.used();
    let wire_bytes = ARC_HEADER + size_of::<Wire>() + size_of::<Application>();
    for headroom in [0, wire_bytes] {
        recycle_bulk(&mut owner, &mut app).await;
        let other = budget
            .reserve(budget.limit() - budget.used() - headroom)
            .unwrap();
        let before = pool.drains();
        let admitted = attach(id, &pool);
        assert_eq!(pool.drains(), before + 1);
        drop((admitted, other));
        assert_eq!(budget.used(), baseline);
    }
}

#[tokio::test]
async fn fallback_stops_at_four_kib_and_slack_never_buys_payload() {
    let ((_, id), _) = connected(Instant::now());
    let budget = MemoryBudget::new(1 << 20);
    let pool = RemoteChunkPool::new(&budget, 1).unwrap();
    let (mut owner, mut app) = attach(id, &pool);
    let baseline = budget.used();
    let small_charge = size_of::<Chunk>() + SMALL_CHUNK;
    let pressure = budget
        .reserve(budget.limit() - baseline - small_charge)
        .unwrap();
    let bytes = [7; BULK_CHUNK];
    assert_eq!(owner.push_rx(&[IoSlice::new(&bytes)]), SMALL_CHUNK);
    assert_eq!(budget.used(), budget.limit());
    drop(pressure);
    owner.push_rx(&[]);
    let mut read = [0; SMALL_CHUNK];
    app.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, &bytes[..SMALL_CHUNK]);
    assert!(!owner.has_unread_rx());
    assert_eq!(budget.used(), baseline);

    for (target, capacity) in [(SMALL_CHUNK, BULK_CHUNK), (BULK_CHUNK, BULK_CHUNK + 1)] {
        let mut chunk = Box::new(Chunk {
            bytes: Vec::with_capacity(capacity),
            memory: budget.reserve(size_of::<Chunk>() + target).unwrap(),
        });
        assert_eq!(chunk.append(&[3; BULK_CHUNK + 1]), target);
        pool.recycle(chunk);
        assert_eq!(budget.used(), baseline);
    }
}

#[tokio::test]
async fn flow_eof_preserves_shard_cache_and_close_refunds_late_returns() {
    let now = Instant::now();
    let ((mut server, first), (mut client, _)) = connected(now);
    let (next, _) = handshake(&mut client, &mut server, now);
    let budget = MemoryBudget::new(1 << 20);
    let pool = RemoteChunkPool::new(&budget, 1).unwrap();
    let (mut owner, mut app) = attach(first, &pool);
    let (mut survivor, mut reader) = attach(next, &pool);
    let baseline = budget.used();
    recycle_bulk(&mut owner, &mut app).await;
    owner.finish_rx(None);
    let mut byte = [0];
    assert_eq!(app.read(&mut byte).await.unwrap(), 0);
    assert_eq!(pool.free.lock().len(), 1);
    assert_eq!(pool.drains(), 0);
    let bytes = [0xab; BULK_CHUNK * 3];
    assert_eq!(survivor.push_rx(&[IoSlice::new(&bytes)]), bytes.len());
    let mut prefix = [0; BULK_CHUNK + 1];
    reader.read_exact(&mut prefix).await.unwrap();
    assert_eq!(prefix, bytes[..prefix.len()]);
    assert_eq!(pool.free.lock().len(), 1);
    let start = std::sync::Barrier::new(2);
    let mut middle = [0; BULK_CHUNK - 1];
    std::thread::scope(|s| {
        s.spawn(|| {
            start.wait();
            pool.close();
        });
        start.wait();
        futures::executor::block_on(reader.read_exact(&mut middle)).unwrap();
    });
    assert_eq!(middle, bytes[prefix.len()..BULK_CHUNK * 2]);
    assert!(pool.free.lock().is_empty());
    assert_eq!(budget.used(), baseline + size_of::<Chunk>() + BULK_CHUNK);
    let mut suffix = [0; BULK_CHUNK];
    reader.read_exact(&mut suffix).await.unwrap();
    assert_eq!(suffix, bytes[BULK_CHUNK * 2..]);
    assert_eq!(budget.used(), baseline);
    assert!(pool.free.lock().is_empty());
    pool.close();
    assert_eq!(pool.drains(), 1);
}
