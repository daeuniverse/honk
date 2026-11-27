use super::*;

fn attach(budget: &Arc<MemoryBudget>, wake_owner: Waker) -> (RemoteOwner, RemoteEndpoint) {
    let ((_, id), _) = connected(Instant::now());
    pair(
        id,
        budget,
        &RemoteChunkPool::new(budget, 1).unwrap(),
        wake_owner,
        Arc::new(0.into()),
        None,
    )
    .unwrap()
}

fn ready_buf<'a>(
    reader: &'a mut (impl AsyncBufRead + Unpin),
    cx: &mut Context<'_>,
) -> io::Result<&'a [u8]> {
    match Pin::new(reader).poll_fill_buf(cx) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("expected receive data or a terminal state"),
    }
}

#[test]
fn buffered_receive_keeps_front_and_drains_before_terminal() {
    fn check(
        reader: &mut (impl AsyncBufRead + Unpin),
        owner: &mut RemoteOwner,
        terminal: Option<StreamError>,
    ) {
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        Pin::new(&mut *reader).consume(0);
        assert!(Pin::new(&mut *reader).poll_fill_buf(&mut cx).is_pending());
        assert_eq!(owner.push_rx(&[IoSlice::new(b"abcd")]), 4);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);

        let first = ready_buf(reader, &mut cx).unwrap();
        assert_eq!(first, b"abcd");
        let pointer = first.as_ptr();
        let repeated = ready_buf(reader, &mut cx).unwrap();
        assert_eq!(repeated, b"abcd");
        assert_eq!(repeated.as_ptr(), pointer);
        Pin::new(&mut *reader).consume(0);
        assert_eq!(ready_buf(reader, &mut cx).unwrap().as_ptr(), pointer);

        assert_eq!(owner.push_rx(&[IoSlice::new(b"efghi")]), 5);
        owner.finish_rx(terminal);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
        Pin::new(&mut *reader).consume(2);
        let tail = ready_buf(reader, &mut cx).unwrap();
        assert_eq!(tail, b"cd");
        assert_eq!(tail.as_ptr(), pointer.wrapping_add(2));
        Pin::new(&mut *reader).consume(2);
        assert_eq!(ready_buf(reader, &mut cx).unwrap(), b"efghi");
        Pin::new(&mut *reader).consume(5);
        assert!(!owner.has_unread_rx());
        Pin::new(&mut *reader).consume(0);
        match terminal {
            None => assert!(ready_buf(reader, &mut cx).unwrap().is_empty()),
            Some(error) => assert_eq!(
                ready_buf(reader, &mut cx).unwrap_err().kind(),
                stream_error(error).kind(),
            ),
        }
    }

    for terminal in [None, Some(StreamError::Reset)] {
        for split in [false, true] {
            let budget = MemoryBudget::new(32 << 10);
            let (mut owner, mut app) = attach(&budget, Waker::noop().clone());
            if split {
                let (mut reader, _) = app.split_mut();
                check(&mut reader, &mut owner, terminal);
            } else {
                check(&mut app, &mut owner, terminal);
            }
        }
    }
}

#[test]
#[should_panic(expected = "consumed 3 bytes from a 2-byte receive buffer")]
fn buffered_receive_rejects_consumption_past_front() {
    let budget = MemoryBudget::new(32 << 10);
    let (mut owner, mut app) = attach(&budget, Waker::noop().clone());
    assert_eq!(owner.push_rx(&[IoSlice::new(b"abc")]), 3);
    assert_eq!(owner.push_rx(&[IoSlice::new(b"def")]), 3);
    let (mut reader, _) = app.split_mut();
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(ready_buf(&mut reader, &mut cx).unwrap(), b"abc");
    Pin::new(&mut reader).consume(1);
    assert_eq!(ready_buf(&mut reader, &mut cx).unwrap(), b"bc");
    Pin::new(&mut reader).consume(3);
}

#[test]
fn buffered_receive_wakes_full_ring_owner_at_low_watermark() {
    let budget = MemoryBudget::new(2 << 20);
    let wakes = Arc::new(Wakes::default());
    let (mut owner, mut app) = attach(&budget, Arc::clone(&wakes).into());
    let payload = vec![0x5a; BULK_CHUNK * SLOTS + 1];
    assert_eq!(owner.push_rx(&[IoSlice::new(&payload)]), payload.len() - 1);
    assert!(owner.wire.rx.full.load(Ordering::Acquire));

    let (mut reader, _) = app.split_mut();
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..SLOTS - WAKE_LOW_WATERMARK - 1 {
        assert_eq!(ready_buf(&mut reader, &mut cx).unwrap().len(), BULK_CHUNK);
        Pin::new(&mut reader).consume(BULK_CHUNK);
    }
    assert_eq!(ready_buf(&mut reader, &mut cx).unwrap().len(), BULK_CHUNK);
    Pin::new(&mut reader).consume(BULK_CHUNK - 1);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
    assert_eq!(
        owner.wire.rx.occupied.load(Ordering::Acquire),
        WAKE_LOW_WATERMARK + 1,
    );

    Pin::new(&mut reader).consume(1);
    assert_eq!(
        wakes.0.load(Ordering::Relaxed),
        1,
        "releasing the whole chunk at the low watermark must wake the blocked RX owner",
    );
    assert_eq!(
        owner.wire.rx.occupied.load(Ordering::Acquire),
        WAKE_LOW_WATERMARK,
    );
    assert_eq!(owner.push_rx(&[IoSlice::new(b"x")]), 1);
}

#[test]
fn receive_credit_wakes_both_budget_waiters() {
    fn copy(reader: &mut RemoteReadHalf<'_>, cx: &mut Context<'_>, expected: &[u8]) {
        let mut bytes = [0; 8];
        let mut buf = ReadBuf::new(&mut bytes[..expected.len()]);
        assert!(matches!(
            Pin::new(reader).poll_read(cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), expected);
    }

    for buffered in [false, true] {
        let budget = MemoryBudget::new(32 << 10);
        let owner_wakes = Arc::new(Wakes::default());
        let (mut owner, mut app) = attach(&budget, Arc::clone(&owner_wakes).into());
        assert_eq!(owner.push_rx(&[IoSlice::new(b"abcd")]), 4);
        assert_eq!(owner.push_rx(&[IoSlice::new(b"efgh")]), 4);
        let _held = budget.reserve(budget.limit() - budget.used()).unwrap();
        assert_eq!(owner.push_rx(&[IoSlice::new(b"blocked")]), 0);
        assert!(owner.wire.rx_budget.load(Ordering::Acquire));
        let (mut reader, mut writer) = app.split_mut();
        let mut rcx = Context::from_waker(Waker::noop());
        let writer_wakes = Arc::new(Wakes::default());
        let writer_waker = Waker::from(Arc::clone(&writer_wakes));
        let mut wcx = Context::from_waker(&writer_waker);
        assert!(
            Pin::new(&mut writer)
                .poll_write(&mut wcx, b"retry")
                .is_pending()
        );
        assert!(owner.wire.tx_budget.load(Ordering::Acquire));
        assert_eq!(owner_wakes.0.load(Ordering::Relaxed), 1);

        if buffered {
            assert_eq!(ready_buf(&mut reader, &mut rcx).unwrap(), b"abcd");
            Pin::new(&mut reader).consume(1);
        } else {
            copy(&mut reader, &mut rcx, b"a");
        }
        assert_eq!(budget.used(), budget.limit());
        assert_eq!(owner.wire.rx.occupied.load(Ordering::Acquire), 2);
        assert_eq!(owner_wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(writer_wakes.0.load(Ordering::Relaxed), 0);

        let freed = if buffered {
            assert_eq!(ready_buf(&mut reader, &mut rcx).unwrap(), b"bcd");
            Pin::new(&mut reader).consume(3);
            1
        } else {
            copy(&mut reader, &mut rcx, b"bcdefgh");
            2
        };
        assert_eq!(
            budget.used(),
            budget.limit() - freed * (size_of::<Chunk>() + SMALL_CHUNK),
        );
        assert_eq!(owner.wire.rx.occupied.load(Ordering::Acquire), 2 - freed);
        assert_eq!(
            owner_wakes.0.load(Ordering::Relaxed),
            2,
            "one RX budget wake per poll or full consume",
        );
        assert_eq!(
            writer_wakes.0.load(Ordering::Relaxed),
            1,
            "the TX budget waiter must be woken",
        );
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut wcx, b"retry"),
            Poll::Ready(Ok(5))
        ));
    }
}

struct ShortWriter<'a> {
    source: &'a [u8],
    pointers: [*const u8; SLOTS],
    written: usize,
}

impl AsyncWrite for ShortWriter<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let index = self.written / BULK_CHUNK;
        let offset = self.written % BULK_CHUNK;
        assert_eq!(bytes.as_ptr(), self.pointers[index].wrapping_add(offset));
        assert_eq!(bytes, &self.source[self.written..(index + 1) * BULK_CHUNK]);
        let n = bytes.len().min(1023);
        self.written += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn borrowed_upload_short_writes_do_not_allocate() {
    fn assert_send_unpin(_: &(impl Send + Unpin)) {}

    const NAME: &str =
        "control::netstack::remote::tests::buffered::borrowed_upload_short_writes_do_not_allocate";
    if crate::test_support::run_exact_in_child("HONK_P11_UPLOAD_ALLOC_CHILD", NAME) {
        return;
    }
    tokio::task::yield_now().await;
    let budget = MemoryBudget::new(2 << 20);
    let (mut owner, mut app) = attach(&budget, Waker::noop().clone());
    let source: Vec<u8> = (0..SLOTS * BULK_CHUNK)
        .map(|i| (i as u8).wrapping_add((i / BULK_CHUNK) as u8))
        .collect();
    assert_eq!(owner.push_rx(&[IoSlice::new(&source)]), source.len());
    owner.finish_rx(None);
    // Snapshot published storage while neither half is polling the ring.
    let pointers = std::array::from_fn(|index| {
        let slot = &owner.wire.rx.slots[index];
        let chunk = slot.take().unwrap();
        assert_eq!(chunk.bytes.len(), BULK_CHUNK);
        let pointer = chunk.bytes.as_ptr();
        slot.store(Some(chunk));
        pointer
    });
    let mut sink = ShortWriter {
        source: &source,
        pointers,
        written: 0,
    };
    let mut cx = Context::from_waker(Waker::noop());
    let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
    let (mut reader, writer) = app.split_mut();
    assert_send_unpin(&reader);
    assert_send_unpin(&writer);
    loop {
        let bytes = ready_buf(&mut reader, &mut cx).unwrap();
        if bytes.is_empty() {
            break;
        }
        let Poll::Ready(Ok(n)) = Pin::new(&mut sink).poll_write(&mut cx, bytes) else {
            panic!("short-write sink must accept bytes immediately");
        };
        assert!(n > 0);
        Pin::new(&mut reader).consume(n);
    }
    let stats = region.change();
    assert_eq!(sink.written, source.len());
    assert!(!owner.has_unread_rx());
    assert_eq!(stats.allocations, 0);
    assert_eq!(stats.reallocations, 0);
    println!("P11_UPLOAD_ALLOCATIONS={}", stats.allocations);
    println!("P11_UPLOAD_REALLOCATIONS={}", stats.reallocations);
    println!("P11_UPLOAD_BYTES={}", sink.written);
}
