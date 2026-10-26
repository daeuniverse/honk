//! The per-mode chunk size with the v2 memory model intact: funded floors, admission, window
//! commitment, idle flows holding nothing.

mod offload_common;

use std::net::SocketAddr;
use std::time::Instant;

use honk_netstack::wire::tcp::{ACK, SYN};
use honk_netstack::{AcceptOpts, Config, DropReason, FlowId, Rx, Stack, StreamError, TcpState};
use offload_common::*;

fn client_n(i: usize) -> SocketAddr {
    format!(
        "10.{}.{}.{}:{}",
        i / 60_000,
        (i / 200) % 250,
        2 + i % 200,
        40_000 + i % 5000
    )
    .parse()
    .unwrap()
}

/// SYNs from `n` distinct clients; accepted ones are returned. Nothing else happens.
fn syns(stack: &mut Stack, n: usize, accept: bool) -> Vec<(FlowId, SocketAddr)> {
    let now = Instant::now();
    let mut flows = Vec::new();
    for i in 0..n {
        let c = client_n(i);
        let syn = build(c, addr(DST), 1000, 0, SYN, opts_syn(1460), &[]);
        stack.receive(now, &syn);
        if let Some(info) = stack.poll_accept() {
            if accept {
                stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
            }
            flows.push((info.id, c));
        }
    }
    flows
}

fn with_chunk(chunk: Option<usize>, limit: usize) -> Config {
    let mut cfg = transparent();
    cfg.tcp_chunk = chunk;
    cfg.memory_limit = limit;
    cfg.max_flows = 4096;
    cfg.half_open_max = 4096;
    cfg.half_open_per_source = 4096;
    cfg
}

/// What one admitted TCP flow is charged at admission, read off a SYN-only flow.
fn floor_of(chunk: Option<usize>) -> usize {
    let mut s = Stack::new(with_chunk(chunk, 1 << 30), Instant::now());
    assert_eq!(syns(&mut s, 1, false).len(), 1);
    s.stats().memory_committed
}

#[test]
fn chunk_size_defaults_follow_the_mode() {
    assert_eq!(
        Config::new([0; 32]).chunk(),
        16 * 1024,
        "endpoint keeps 16 KiB"
    );
    assert_eq!(
        transparent().chunk(),
        4 * 1024,
        "transparent defaults to 4 KiB"
    );
    let mut cfg = transparent();
    for (set, want) in [
        (Some(1), 4096),
        (Some(8192), 8192),
        (Some(1 << 20), 65536),
        (Some(16384), 16384),
        (None, 4096),
    ] {
        cfg.tcp_chunk = set;
        assert_eq!(cfg.chunk(), want);
    }
    let mut cfg = Config::new([0; 32]);
    cfg.tcp_chunk = Some(4096);
    assert_eq!(cfg.chunk(), 4096, "an endpoint may opt into small chunks");
}

#[test]
fn the_transparent_floor_is_about_nine_kib_and_scales_with_the_chunk() {
    let f4 = floor_of(None);
    let f16 = floor_of(Some(16 * 1024));
    assert!(
        (2 * 4096..10 * 1024).contains(&f4),
        "two 4 KiB chunks plus the descriptor floor: {f4}"
    );
    assert_eq!(
        f16 - f4,
        2 * (16 * 1024 - 4096),
        "only the two chunks scale"
    );
    assert_eq!(floor_of(Some(4096)), f4);
}

#[test]
fn admission_stops_exactly_at_the_funded_floors() {
    let f4 = floor_of(None);
    let f16 = floor_of(Some(16 * 1024));
    let limit = 10 * f4 + f4 / 2;
    for (chunk, floor) in [(None, f4), (Some(16 * 1024), f16)] {
        let mut s = Stack::new(with_chunk(chunk, limit), Instant::now());
        let flows = syns(&mut s, 40, true);
        assert_eq!(flows.len(), limit / floor, "chunk {chunk:?}");
        let st = s.stats();
        assert_eq!(
            st.drops[DropReason::Capacity as usize],
            (40 - flows.len()) as u64
        );
        assert!(st.memory_committed <= limit);
        assert!(st.memory_committed >= flows.len() * floor);
    }
    // Endpoint mode: the same arithmetic with 16 KiB chunks, as before.
    let mut cfg = Config::new([5; 32]);
    cfg.local_v4 = Some("10.0.0.2".parse().unwrap());
    cfg.memory_limit = 7 * f16 + 100;
    let mut s = Stack::new(cfg, Instant::now());
    let mut n = 0;
    while s
        .tcp_connect(Instant::now(), addr(&format!("203.0.113.{}:443", 1 + n)))
        .is_ok()
    {
        n += 1;
        assert!(n < 100);
    }
    assert_eq!(n, 7);
}

/// A flow whose handshake is complete.
fn established(s: &mut Stack, c: SocketAddr, isn: u32, now: Instant) -> (FlowId, u32, u32) {
    let syn = build(c, addr(DST), isn, 0, SYN, opts_syn(1460), &[]);
    s.receive(now, &syn);
    let info = s.poll_accept().unwrap();
    s.tcp_accept(info.id, AcceptOpts::default()).unwrap();
    let mut buf = [0u8; 2000];
    let n = s.poll_transmit(now, &mut buf).unwrap();
    let synack = decode(&buf[..n]);
    let (snd, tsval) = (
        synack.h.seq.wrapping_add(1),
        synack.h.options.timestamps.unwrap().0,
    );
    let o = honk_netstack::wire::tcp::Options {
        timestamps: Some((5001, tsval)),
        ..Default::default()
    };
    let ack = build(c, addr(DST), isn + 1, snd, ACK, o, &[]);
    assert_eq!(s.receive(now + ms(1), &ack), Rx::Consumed);
    assert_eq!(s.tcp_state(info.id), Some(TcpState::Established));
    (info.id, snd, tsval)
}

#[test]
fn idle_flows_hold_no_chunks() {
    for (chunk, want_max) in [(None, 4096), (Some(16 * 1024), 16 * 1024)] {
        let mut s = Stack::new(with_chunk(chunk, 256 << 20), Instant::now());
        let now = Instant::now();
        for i in 0..50 {
            let (id, snd, echo) = established(&mut s, client_n(i), 1000, now);
            let options = honk_netstack::wire::tcp::Options {
                timestamps: Some((5002, echo)),
                ..Default::default()
            };
            let packet = build(client_n(i), addr(DST), 1001, snd, ACK, options, &[9; 100]);
            assert_eq!(s.receive(now + ms(2), &packet), Rx::Consumed);
            let mut out = [0; 100];
            assert_eq!(s.tcp_read(id, &mut out), Ok(100));
            assert_eq!(out, [9; 100]);
            let mut packet = [0; 2000];
            while s.poll_transmit(now + ms(2), &mut packet).is_some() {}
        }
        let st = s.stats();
        assert_eq!(st.flows, 50);
        assert!(
            st.memory_allocated <= want_max,
            "50 idle flows own no buffer, only the pool's one spare chunk: {} with chunk {chunk:?}",
            st.memory_allocated
        );
        assert!(
            st.memory_committed > 50 * floor_of(chunk),
            "windows are committed"
        );
        assert!(st.memory_committed <= 256 << 20);
    }
}

#[test]
fn the_floor_alone_keeps_both_directions_moving() {
    // Memory for exactly three floors and nothing to share: every flow gets one chunk each way.
    let f = floor_of(None);
    let mut s = Stack::new(with_chunk(None, 3 * f), Instant::now());
    let mut now = Instant::now();
    let c = client_n(0);
    let (id, mut snd, tsval) = established(&mut s, c, 1000, now);
    let st = s.tcp_stats(id).unwrap();
    assert_eq!(st.receive_committed, 4096, "one chunk, no shared memory");
    assert!(st.receive_window <= 4096);
    let mut seq = 1001u32;
    let mut ts = 5001;
    let mut received = Vec::new();
    let mut buf = vec![0u8; 20_000];
    for round in 0..10 {
        now += ms(1);
        // 4096 bytes in three segments fill the window exactly; more would be cut off.
        let data = pattern(4096 + 500, round);
        for part in [&data[..1368], &data[1368..2736], &data[2736..]] {
            ts += 1;
            let o = honk_netstack::wire::tcp::Options {
                timestamps: Some((ts, tsval)),
                ..Default::default()
            };
            let p = build(c, addr(DST), seq, snd, ACK, o, part);
            let accepted_before = s.tcp_stats(id).unwrap().receive_window as usize;
            s.receive(now, &p);
            let take = part.len().min(accepted_before);
            seq = seq.wrapping_add(take as u32);
            if take < part.len() {
                break;
            }
        }
        let n = s.tcp_read(id, &mut buf).expect("the floor makes progress");
        assert!(n > 0, "no progress in round {round}");
        received.extend_from_slice(&buf[..n]);
        assert!(n <= 4096, "never more than the floor's chunk: {n}");
        let st = s.tcp_stats(id).unwrap();
        assert!(st.receive_window as usize <= st.receive_committed);
        assert!(s.stats().memory_committed <= 3 * f);
        // Drain the ACK so the window update goes out and the next round has room.
        let mut out = [0u8; 2000];
        while s.poll_transmit(now, &mut out).is_some() {}
    }
    assert!(received.len() >= 10 * 4000, "{}", received.len());

    // TX: one chunk accepted at a time, then acknowledged, ten times over.
    let payload = pattern(100_000, 9);
    let mut total = 0;
    for _ in 0..10 {
        now += ms(1);
        let n = s.tcp_write(id, &payload[total..]).unwrap();
        assert_eq!(
            n, 4096,
            "the floor's chunk and nothing from the shared pool"
        );
        assert_eq!(
            s.tcp_write(id, &payload[total + n..]),
            Err(StreamError::WouldBlock)
        );
        let mut out = vec![0u8; 2000];
        let mut sent = 0;
        let mut last_ts = tsval;
        while let Some(len) = s.poll_transmit(now, &mut out) {
            let p = decode(&out[..len]);
            sent += p.payload.len();
            last_ts = p.h.options.timestamps.unwrap().0;
        }
        assert_eq!(sent, 4096);
        total += sent;
        snd = snd.wrapping_add(sent as u32);
        ts += 1;
        let o = honk_netstack::wire::tcp::Options {
            timestamps: Some((ts, last_ts)),
            ..Default::default()
        };
        let ack = build(c, addr(DST), seq, snd, ACK, o, &[]);
        assert_eq!(s.receive(now + ms(1), &ack), Rx::Consumed);
        s.handle_timeout(now + ms(1));
    }
    assert_eq!(total, 40_960);
    assert!(s.stats().memory_allocated <= 2 * 4096 + 4096);
}

#[test]
fn a_shared_pool_is_split_without_starving_any_floor() {
    // Three floors plus eight shared chunks: the first flow's window may use the shared ones, the
    // others still have their own chunk; no window is wider than what was committed for it.
    let f = floor_of(None);
    let limit = 3 * f + 8 * 4096;
    let mut cfg = with_chunk(None, limit);
    cfg.max_flows = 3; // else the spare memory would fund more floors instead of sharing
    let mut s = Stack::new(cfg, Instant::now());
    let now = Instant::now();
    let flows: Vec<_> = (0..3)
        .map(|i| established(&mut s, client_n(i), 1000, now).0)
        .collect();
    let mut widest = 0;
    for id in &flows {
        let st = s.tcp_stats(*id).unwrap();
        assert!(st.receive_window as usize <= st.receive_committed, "{st:?}");
        assert!(
            st.receive_window >= 4096,
            "every flow keeps its floor's chunk"
        );
        widest = widest.max(st.receive_window);
    }
    assert_eq!(
        widest as usize,
        9 * 4096,
        "the shared chunks went to the earliest window"
    );
    assert!(s.stats().memory_committed <= limit);
    assert_eq!(
        s.stats().memory_committed,
        limit,
        "everything is committed, nothing over"
    );
}
