use std::io::{self, IoSliceMut};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use honk_netstack::{AcceptOpts, ExcludeSet, MemoryBudget, Mode, TcpConsumeError};

use super::*;

const CHUNK: usize = 4096;
const WINDOW: usize = 6 * CHUNK;

struct Pair {
    client: Stack,
    server: Stack,
    cid: FlowId,
    sid: FlowId,
    now: Instant,
    budget: Arc<MemoryBudget>,
}

fn pair() -> Pair {
    pair_with_window(WINDOW)
}

fn pair_with_window(window: usize) -> Pair {
    let mut cfg = config();
    // An independently deliverable wire segment can cover more than four ring chunks.
    cfg.mtu = 32768;
    cfg.max_flows = 1;
    cfg.memory_limit = 256 * 1024;
    cfg.tcp_chunk = Some(CHUNK);
    cfg.tcp_rcv_buf_max = window;
    cfg.tcp_snd_buf_max = window + CHUNK;
    let mut now = Instant::now();
    let mut client = Stack::new(cfg.clone(), now);
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg.shared_budget = Some(budget.clone());
    let mut server = Stack::new_accounted(cfg, now, 1).unwrap();

    let cid = client.tcp_connect(now, remote(false)).unwrap();
    let syn = pull(&mut client, now).unwrap();
    assert_eq!(server.receive(now, &syn.bytes), Rx::Consumed);
    let sid = server.poll_accept().unwrap().id;
    server.tcp_accept(sid, AcceptOpts::default()).unwrap();
    let syn_ack = pull(&mut server, now).unwrap();
    now += Duration::from_millis(1);
    assert_eq!(client.receive(now, &syn_ack.bytes), Rx::Consumed);
    let ack = pull(&mut client, now).unwrap();
    now += Duration::from_millis(1);
    assert_eq!(server.receive(now, &ack.bytes), Rx::Consumed);
    assert_eq!(server.tcp_state(sid), Some(TcpState::Established));
    assert_eq!(client.tcp_state(cid), Some(TcpState::Established));
    assert!(events(&mut server, sid).contains(Ready::CONNECTED));
    assert!(events(&mut client, cid).contains(Ready::CONNECTED));
    client.take_tx_wakeup();
    server.take_tx_wakeup();
    Pair {
        client,
        server,
        cid,
        sid,
        now,
        budget,
    }
}

fn fill(parts: &mut [IoSliceMut<'_>], data: &[u8]) -> usize {
    let mut copied = 0;
    for part in parts {
        let n = part.len().min(data.len() - copied);
        part[..n].copy_from_slice(&data[copied..copied + n]);
        copied += n;
    }
    assert_eq!(copied, data.len());
    copied
}

fn expect_rx(stack: &Stack, id: FlowId, limit: usize, lengths: &[usize], expected: &[u8]) {
    let (parts, count, eof) = stack.tcp_peek_rx(id, limit).unwrap();
    assert!(!eof);
    assert!(parts[count..].iter().all(|part| part.is_empty()));
    assert!(
        parts[..count]
            .iter()
            .map(|part| part.len())
            .eq(lengths.iter().copied())
    );
    assert!(
        parts[..count]
            .iter()
            .flat_map(|part| part.iter())
            .eq(expected)
    );
}

#[test]
fn vectored_receive_stops_at_the_gap_and_reopens_the_window() {
    let mut p = pair();
    let data = pattern(WINDOW);
    let prefix = CHUNK - 3;
    let gap_end = prefix + 7;
    assert!(matches!(
        p.server.tcp_peek_rx(p.sid, 1),
        Err(StreamError::WouldBlock)
    ));

    assert_eq!(p.client.tcp_write(p.cid, &data[..prefix]), Ok(prefix));
    let first = pull_paced(&mut p.client, &mut p.now).unwrap();
    assert_eq!(first.data(), &data[..prefix]);
    let n = p
        .client
        .tcp_reserve_tx(p.cid, WINDOW, |parts| {
            assert!(parts.iter().map(|part| part.len()).eq([
                3,
                CHUNK,
                CHUNK,
                CHUNK,
                CHUNK,
                CHUNK,
                CHUNK - 3
            ]));
            Ok(fill(parts, &data[prefix..gap_end]))
        })
        .unwrap()
        .unwrap();
    assert_eq!(n, gap_end - prefix);
    let gap = pull_paced(&mut p.client, &mut p.now).unwrap();
    assert_eq!(gap.data(), &data[prefix..gap_end]);
    assert_eq!(
        p.client.tcp_write(p.cid, &data[gap_end..]),
        Ok(WINDOW - gap_end)
    );
    let tail = pull_paced(&mut p.client, &mut p.now).unwrap();
    assert_eq!(tail.data(), &data[gap_end..]);

    assert_eq!(p.server.receive(p.now, &first.bytes), Rx::Consumed);
    assert_eq!(p.server.receive(p.now, &tail.bytes), Rx::Consumed);
    p.server.take_tx_wakeup();
    let committed = p.server.stats().memory_committed;
    assert_eq!(
        p.server.tcp_consume_rx(p.sid, prefix + 1),
        Err(TcpConsumeError::OutOfRange)
    );
    assert_eq!(p.server.tcp_consume_rx(p.sid, 0), Ok(()));
    expect_rx(&p.server, p.sid, WINDOW, &[prefix], &data[..prefix]);
    assert_eq!(p.server.stats().memory_committed, committed);
    assert!(!p.server.take_tx_wakeup());

    assert_eq!(p.server.receive(p.now, &gap.bytes), Rx::Consumed);
    let zero_window = pull(&mut p.server, p.now).unwrap();
    assert_eq!(zero_window.h.ack, tail.end());
    assert_eq!(zero_window.h.window, 0);
    assert_eq!(p.client.receive(p.now, &zero_window.bytes), Rx::Consumed);
    expect_rx(&p.server, p.sid, WINDOW, &[CHUNK; 6], &data);
    expect_rx(
        &p.server,
        p.sid,
        CHUNK + 13,
        &[CHUNK, 13],
        &data[..CHUNK + 13],
    );

    let consumed = CHUNK - 5;
    p.server.take_tx_wakeup();
    assert_eq!(p.server.tcp_consume_rx(p.sid, consumed), Ok(()));
    assert!(p.server.take_tx_wakeup());
    let update = pull(&mut p.server, p.now).unwrap();
    assert_eq!(update.h.ack, zero_window.h.ack);
    assert_eq!(usize::from(update.h.window), consumed);
    assert_eq!(p.client.receive(p.now, &update.bytes), Rx::Consumed);

    p.client.tcp_shutdown(p.cid).unwrap();
    let fin = pull(&mut p.client, p.now).unwrap();
    assert_ne!(fin.h.flags & tcp::FIN, 0);
    assert_eq!(p.server.receive(p.now, &fin.bytes), Rx::Consumed);
    expect_rx(
        &p.server,
        p.sid,
        WINDOW,
        &[5, CHUNK, CHUNK, CHUNK, CHUNK, CHUNK],
        &data[consumed..],
    );
    p.server
        .tcp_consume_rx(p.sid, 4 * CHUNK - consumed)
        .unwrap();
    let mut last = vec![0; 2 * CHUNK];
    assert_eq!(p.server.tcp_read(p.sid, &mut last), Ok(last.len()));
    assert_eq!(last.as_slice(), &data[4 * CHUNK..]);
    let (_, count, eof) = p.server.tcp_peek_rx(p.sid, WINDOW).unwrap();
    assert_eq!((count, eof), (0, true));

    let reply = b"reply after the client's FIN";
    let n = p
        .server
        .tcp_reserve_tx(p.sid, reply.len(), |parts| Ok(fill(parts, reply)))
        .unwrap()
        .unwrap();
    assert_eq!(n, reply.len());
    let response = pull(&mut p.server, p.now).unwrap();
    assert_eq!(p.client.receive(p.now, &response.bytes), Rx::Consumed);
    p.server.tcp_abort(p.sid);
    let reset = pull(&mut p.server, p.now).unwrap();
    assert_ne!(reset.h.flags & tcp::RST, 0);
    assert_eq!(p.client.receive(p.now, &reset.bytes), Rx::Consumed);
    expect_rx(&p.client, p.cid, WINDOW, &[reply.len()], reply);
    p.client.tcp_consume_rx(p.cid, reply.len()).unwrap();
    assert!(matches!(
        p.client.tcp_peek_rx(p.cid, WINDOW),
        Err(StreamError::Reset)
    ));
}

#[test]
fn vectored_stream_spans_64_kib_at_unaligned_offsets() {
    const BYTES: usize = 64 << 10;
    let mut p = pair_with_window(96 << 10);
    let prefix = CHUNK - 1;
    let data = pattern(prefix + BYTES);
    let mut lengths = [CHUNK; 17];
    lengths[0] = 1;
    lengths[16] = CHUNK - 1;

    assert_eq!(p.client.tcp_write(p.cid, &data[..prefix]), Ok(prefix));
    let first = pull_paced(&mut p.client, &mut p.now).unwrap();
    assert_eq!(first.data(), &data[..prefix]);
    let committed = p
        .client
        .tcp_reserve_tx(p.cid, BYTES, |parts| {
            assert!(parts.iter().map(|part| part.len()).eq(lengths));
            Ok(fill(parts, &data[prefix..]))
        })
        .unwrap()
        .unwrap();
    assert_eq!(committed, BYTES);

    let second = pull_paced(&mut p.client, &mut p.now).unwrap();
    assert!(!second.data().is_empty());
    // Leave buffered data at the last byte of a chunk, and grow the advertised window
    // past the initial 65,535 bytes so the entire loan can be received without another read.
    p.now += Duration::from_millis(100);
    assert_eq!(p.server.receive(p.now, &first.bytes), Rx::Consumed);
    assert_eq!(p.server.receive(p.now, &second.bytes), Rx::Consumed);
    assert_eq!(p.server.tcp_consume_rx(p.sid, prefix), Ok(()));
    let update = pull(&mut p.server, p.now).unwrap();
    assert_eq!(update.h.ack, second.end());
    assert_eq!(p.client.receive(p.now, &update.bytes), Rx::Consumed);

    let mut received = second.data().len();
    while received < BYTES {
        let packet = pull_paced(&mut p.client, &mut p.now).unwrap();
        assert!(!packet.data().is_empty());
        received += packet.data().len();
        assert_eq!(p.server.receive(p.now, &packet.bytes), Rx::Consumed);
    }
    assert_eq!(received, BYTES);
    expect_rx(&p.server, p.sid, BYTES, &lengths, &data[prefix..]);
}

#[test]
fn single_chunk_tx_loan_reuses_an_unaligned_funded_tail() {
    let mut p = pair();
    let used = p.budget.used();
    let held = p.budget.reserve(p.budget.limit() - used).unwrap();
    let data = pattern(CHUNK);
    let filled = p
        .server
        .tcp_reserve_tx_chunk(p.sid, CHUNK, |parts| {
            assert!(parts.iter().map(|part| part.len()).eq([CHUNK]));
            Ok(fill(parts, &data[..CHUNK - 1]))
        })
        .unwrap()
        .unwrap();
    assert_eq!(filled, CHUNK - 1);
    assert!(p.server.take_tx_wakeup());
    drop(held);

    let error = p
        .server
        .tcp_reserve_tx_chunk(p.sid, CHUNK, |parts| {
            assert!(parts.iter().map(|part| part.len()).eq([1]));
            assert_eq!(p.budget.used(), used);
            Err(io::ErrorKind::WouldBlock.into())
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(p.budget.used(), used);
    assert!(!p.server.take_tx_wakeup());

    let held = p.budget.reserve(p.budget.limit() - used).unwrap();
    let filled = p
        .server
        .tcp_reserve_tx_chunk(p.sid, CHUNK, |parts| Ok(fill(parts, &data[CHUNK - 1..])))
        .unwrap()
        .unwrap();
    assert_eq!(filled, 1);
    assert!(matches!(
        p.server
            .tcp_reserve_tx_chunk(p.sid, CHUNK, |_| panic!("unfunded second chunk")),
        Err(StreamError::WouldBlock)
    ));
    assert!(p.server.has_pending_writers());
    drop(held);
    assert_eq!(p.budget.used(), used);
    let packet = pull_paced(&mut p.server, &mut p.now).unwrap();
    assert_eq!(packet.data(), data);
}

#[test]
fn vectored_send_refunds_unused_credit_and_retransmits_after_close() {
    let mut p = pair();
    let base_committed = p.server.stats().memory_committed;
    let data = pattern(5 * CHUNK + 13);
    let n = p
        .server
        .tcp_reserve_tx(p.sid, 4 * CHUNK, |parts| {
            Ok(fill(parts, &data[..4 * CHUNK]))
        })
        .unwrap()
        .unwrap();
    assert_eq!(n, 4 * CHUNK);
    assert!(p.server.take_tx_wakeup());

    let used = p.budget.used();
    let held = p.budget.reserve(p.budget.limit() - used - CHUNK).unwrap();
    assert!(matches!(
        p.server
            .tcp_reserve_tx(p.sid, 1, |_| panic!("unfunded fifth chunk")),
        Err(StreamError::WouldBlock)
    ));
    assert_eq!(p.budget.used(), used + held.bytes());
    assert!(!events(&mut p.server, p.sid).contains(Ready::WRITABLE));
    assert!(p.server.has_pending_writers());
    drop(held);
    p.server.handle_timeout(p.now);
    assert!(events(&mut p.server, p.sid).contains(Ready::WRITABLE));
    assert!(events(&mut p.server, p.sid).is_empty());
    assert!(!p.server.has_pending_writers());

    let n = p
        .server
        .tcp_reserve_tx(p.sid, 0, |_| panic!("zero limit must skip the callback"))
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    let n = p
        .server
        .tcp_reserve_tx(p.sid, 1, |parts| {
            assert!(parts.iter().map(|part| part.len()).eq([1]));
            assert!((CHUNK..2 * CHUNK).contains(&(p.budget.used() - used)));
            parts[0][0] = 0xff;
            Ok(0)
        })
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(p.budget.used(), used);

    let error = p
        .server
        .tcp_reserve_tx(p.sid, usize::MAX, |parts| {
            assert!(parts.iter().map(|part| part.len()).eq([CHUNK; 3]));
            parts[0].fill(0xff);
            Err(io::ErrorKind::WouldBlock.into())
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(p.budget.used(), used);
    let error = p
        .server
        .tcp_reserve_tx(p.sid, 1, |_| Ok(2))
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(p.budget.used(), used);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            p.server
                .tcp_reserve_tx(p.sid, CHUNK, |_| panic!("abandon loan"))
        }))
        .is_err()
    );
    assert_eq!(p.budget.used(), used);
    assert!(!p.server.take_tx_wakeup());
    assert_eq!(
        p.server.stats().memory_committed,
        base_committed + 3 * CHUNK
    );

    let n = p
        .server
        .tcp_reserve_tx(p.sid, usize::MAX, |parts| {
            Ok(fill(parts, &data[4 * CHUNK..]))
        })
        .unwrap()
        .unwrap();
    assert_eq!(n, CHUNK + 13);
    assert!(p.server.take_tx_wakeup());
    assert_eq!(
        p.server.stats().memory_committed,
        base_committed + 5 * CHUNK
    );
    p.server.tcp_close(p.sid);
    assert!(p.server.tcp_retained(p.sid));
    assert_eq!(
        p.server.tcp_consume_rx(p.sid, 0),
        Err(TcpConsumeError::Stale)
    );
    assert!(matches!(
        p.server
            .tcp_reserve_tx(p.sid, 1, |_| panic!("closed handle")),
        Err(StreamError::Stale)
    ));
    let lost = pull_paced(&mut p.server, &mut p.now).unwrap();
    assert_eq!(lost.data(), data.as_slice());
    assert_ne!(lost.h.flags & tcp::FIN, 0);
    p.now = p.server.poll_timeout().unwrap();
    p.server.handle_timeout(p.now);
    let retry = pull_paced(&mut p.server, &mut p.now).unwrap();
    assert_eq!(retry.h.seq, lost.h.seq);
    assert_eq!(retry.data(), data.as_slice());
    assert_eq!(
        p.server.stats().memory_committed,
        base_committed + 5 * CHUNK
    );
    assert_eq!(p.client.receive(p.now, &retry.bytes), Rx::Consumed);
    let ack = pull(&mut p.client, p.now).unwrap();
    assert_eq!(ack.h.ack, lost.end());
    assert_eq!(p.server.receive(p.now, &ack.bytes), Rx::Consumed);
    assert_eq!(p.server.stats().memory_committed, base_committed);
    drop(p.server);
    assert_eq!(p.budget.used(), 0);
}
