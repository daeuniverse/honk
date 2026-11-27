use super::*;
use crate::wire::tcp::{self, Header, Options};

const CHUNK: usize = 4096;
const MSS: u16 = 2048;

fn stack(budget: Option<Arc<MemoryBudget>>, snd_max: usize, now: Instant) -> Stack {
    let mut cfg = Config::new([90; 32]);
    cfg.local_v4 = Some(Ipv4Addr::LOCALHOST);
    cfg.tcp_chunk = Some(CHUNK);
    cfg.tcp_snd_buf_max = snd_max;
    cfg.mtu = MSS + 40;
    cfg.shared_budget = budget;
    Stack::new(cfg, now)
}

fn peer_ack(s: &mut Stack, id: FlowId, ack: u32, syn: bool, window: u16) {
    let Some(Flow::Tcp(t)) = s.table.get(id) else {
        panic!("missing flow")
    };
    let tuple = t.tuple;
    let h = Header {
        src_port: tuple.remote.port(),
        dst_port: tuple.local.port(),
        seq: if syn { 17 } else { t.rcv_nxt },
        ack,
        flags: if syn { tcp::SYN | tcp::ACK } else { tcp::ACK },
        window,
        urgent: 0,
        options: Options {
            mss: syn.then_some(MSS),
            ..Options::default()
        },
    };
    let mut packet = [0; 80];
    let n = tcp::emit_packet(
        &mut packet,
        tuple.remote.ip(),
        tuple.local.ip(),
        &h,
        [&[], &[]],
    )
    .unwrap();
    assert_eq!(s.receive(s.now, &packet[..n]), Rx::Consumed);
}

fn open(s: &mut Stack, port: u16, window: u16) -> FlowId {
    let id = s
        .tcp_connect(s.now, SocketAddr::from(([192, 0, 2, 2], port)))
        .unwrap();
    let mut packet = [0; 80];
    assert_eq!(
        s.poll_transmit_with(s.now, &mut packet, TxCaps::NONE)
            .unwrap()
            .flow,
        Some(id)
    );
    let Some(Flow::Tcp(t)) = s.table.get(id) else {
        unreachable!()
    };
    let ack = t.iss.wrapping_add(1);
    peer_ack(s, id, ack, true, window);
    assert!(s.poll_transmit(s.now, &mut packet).is_some());
    assert!(s.poll_event().unwrap().1.contains(Ready::CONNECTED));
    id
}

#[test]
fn full_local_buffers_on_zero_window_flows_do_not_scan_pool_waiters() {
    let mut s = stack(None, CHUNK, Instant::now());
    let ids: Vec<_> = (1..=500).map(|port| open(&mut s, port, 0)).collect();
    for id in ids {
        assert_eq!(s.tcp_write(id, &[7; CHUNK]), Ok(CHUNK));
        assert_eq!(s.tcp_write(id, &[8]), Err(StreamError::WouldBlock));
    }
    assert!(s.writers.is_empty());
    assert!(!s.has_pending_writers());
    assert!(s.poll_event().is_none());
    assert_eq!(s.writer_visits, 0);
}

fn ack_grows_room(s: &mut Stack, id: FlowId, budget_hog: Option<&mut Pool>) {
    let Some(Flow::Tcp(t)) = s.table.get(id) else {
        unreachable!()
    };
    let cwnd = t.cc.cwnd();
    let limit = 2 * cwnd as usize;
    assert_eq!(s.tcp_write(id, &vec![9; limit]), Ok(limit));
    assert_eq!(s.tcp_write(id, &[8]), Err(StreamError::WouldBlock));
    assert!(s.writers.is_empty());
    let mut out = [0; MSS as usize + 40];
    assert_eq!(s.poll_transmit(s.now, &mut out), Some(out.len()));
    let Some(Flow::Tcp(t)) = s.table.get_mut(id) else {
        unreachable!()
    };
    t.cwnd_limited = true;
    let ack = t.snd_nxt;
    if let Some(hog) = budget_hog {
        assert!(hog.reserve_bytes(s.cfg.shared_budget.as_ref().unwrap().available()));
    }
    peer_ack(s, id, ack, false, u16::MAX);
    let Some(Flow::Tcp(t)) = s.table.get(id) else {
        unreachable!()
    };
    assert!(t.cc.cwnd() > cwnd);
}

#[test]
fn ack_cwnd_growth_crosses_the_writable_threshold() {
    let mut s = stack(None, 128 << 10, Instant::now());
    let id = open(&mut s, 443, u16::MAX);
    ack_grows_room(&mut s, id, None);
    assert_eq!(s.poll_event(), Some((id, Ready::WRITABLE)));
    assert_eq!(s.tcp_write(id, &[1; CHUNK]), Ok(CHUNK));
}

#[test]
fn ack_promotes_a_pool_waiter_until_another_stack_refunds() {
    let now = Instant::now();
    let budget = MemoryBudget::new(1 << 20);
    let mut other = stack(Some(budget.clone()), 128 << 10, now);
    let mut s = stack(Some(budget), 128 << 10, now);
    let id = open(&mut s, 443, u16::MAX);
    ack_grows_room(&mut s, id, Some(&mut other.pool));
    assert_eq!(s.writers.len(), 1);
    assert!(s.poll_event().is_none());
    other.pool.release(1);
    s.handle_timeout(now);
    assert_eq!(s.poll_event(), Some((id, Ready::WRITABLE)));
    assert_eq!(s.tcp_write(id, &[1; CHUNK]), Ok(CHUNK));
}

#[test]
fn returned_tx_loan_credit_wakes_a_borrowed_writer_on_another_stack() {
    let now = Instant::now();
    let budget = MemoryBudget::new(1 << 20);
    let mut donor = stack(Some(budget.clone()), 128 << 10, now);
    let mut waiter = stack(Some(budget.clone()), 128 << 10, now);
    let donor_id = open(&mut donor, 443, u16::MAX);
    let waiter_id = open(&mut waiter, 8443, u16::MAX);
    assert_eq!(
        waiter
            .tcp_reserve_tx_chunk(waiter_id, CHUNK, |parts| {
                parts[0].fill(1);
                Ok(CHUNK)
            })
            .unwrap()
            .unwrap(),
        CHUNK
    );
    let _held = budget.reserve(budget.available() - CHUNK).unwrap();
    let epoch = budget.release_epoch();
    assert_eq!(
        donor
            .tcp_reserve_tx(donor_id, 2 * CHUNK, |parts| {
                assert_eq!(parts.len(), 2);
                assert_eq!(budget.available(), 0);
                assert!(matches!(
                    waiter.tcp_reserve_tx_chunk(waiter_id, CHUNK, |_| panic!("unfunded loan")),
                    Err(StreamError::WouldBlock)
                ));
                assert!(waiter.has_pending_writers());
                assert!(waiter.poll_event().is_none());
                Ok(0)
            })
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(budget.available(), CHUNK);
    assert_ne!(budget.release_epoch(), epoch);
    assert_eq!(waiter.poll_event(), Some((waiter_id, Ready::WRITABLE)));
    assert!(!waiter.has_pending_writers());
    assert!(waiter.poll_event().is_none());
    assert_eq!(
        waiter
            .tcp_reserve_tx_chunk(waiter_id, CHUNK, |parts| {
                parts[0].fill(2);
                Ok(CHUNK)
            })
            .unwrap()
            .unwrap(),
        CHUNK
    );
    assert_eq!(budget.available(), 0);
}

#[test]
fn local_pool_refunds_wake_without_a_shared_budget() {
    let mut s = stack(None, 128 << 10, Instant::now());
    let id = open(&mut s, 443, u16::MAX);
    assert_eq!(s.tcp_write(id, &[1; CHUNK]), Ok(CHUNK));
    let free = s.pool.shared_free();
    assert!(s.pool.reserve(free));
    assert_eq!(s.tcp_write(id, &[2]), Err(StreamError::WouldBlock));
    let before = s.writer_visits;
    assert!(s.poll_event().is_none());
    assert_eq!(s.writer_visits, before);
    s.pool.release(1);
    assert_eq!(s.poll_event(), Some((id, Ready::WRITABLE)));
    assert_eq!(s.tcp_write(id, &[2; CHUNK]), Ok(CHUNK));
}
