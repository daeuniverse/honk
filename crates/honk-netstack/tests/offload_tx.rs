//! TSO/USO transmit: segmentation correctness against an independent kernel model, window,
//! pacing and descriptor bookkeeping, retransmission, and "caps off means the old behaviour".

mod offload_common;

use std::time::{Duration, Instant};

use honk_netstack::wire::tcp::{self, ACK, FIN, PSH};
use honk_netstack::wire::{self, PROTO_TCP, PROTO_UDP};
use honk_netstack::{
    Config, GsoKind, Rx, Stack, StreamError, TcpState, Transmit, TxCaps, TxCsum, UdpError,
};
use offload_common::*;

struct Bulk {
    received: Vec<u8>,
    packets: usize,
    tso_packets: usize,
    max_segs: usize,
    max_payload: usize,
    first_tso: Option<(Transmit, Pkt)>,
}

/// Checks one emitted packet the way the receiving kernel would and returns its payload.
fn check_packet(t: &Transmit, p: &Pkt) -> usize {
    assert_eq!(t.len, p.raw.len());
    match t.gso {
        None => {
            assert_eq!(t.csum, TxCsum::Full);
            assert!(
                tcp::verify_checksum(p.src.ip(), p.dst.ip(), &p.raw[p.ip_len..]),
                "a plain packet carries a complete checksum"
            );
            1
        }
        Some(g) => {
            assert_eq!(g.kind, GsoKind::Tcp);
            assert_eq!(
                t.csum,
                TxCsum::Partial {
                    start: p.ip_len as u16,
                    offset: 16
                }
            );
            let seg_len = p.tcp_len + p.payload.len();
            let seed = pseudo_seed(p.src.ip(), p.dst.ip(), PROTO_TCP, seg_len);
            let field = u16::from_be_bytes([p.raw[p.ip_len + 16], p.raw[p.ip_len + 17]]);
            assert_eq!(
                field, seed,
                "the field holds the pseudo-header sum of the whole packet"
            );
            // The NIC completes the checksum of the whole packet: it must come out valid.
            let mut whole = p.raw.clone();
            complete_checksum(&mut whole, p.ip_len, 16);
            assert!(tcp::verify_checksum(
                p.src.ip(),
                p.dst.ip(),
                &whole[p.ip_len..]
            ));
            // And every segment the kernel cuts is a valid, well-formed packet.
            let segs = tso_segments(t, p);
            let mut rebuilt = Vec::new();
            for (i, s) in segs.iter().enumerate() {
                let q = decode(s);
                assert!(tcp::verify_checksum(q.src.ip(), q.dst.ip(), &s[q.ip_len..]));
                assert_eq!(
                    q.h.seq,
                    p.h.seq.wrapping_add((i * usize::from(g.size)) as u32)
                );
                assert!(q.payload.len() <= usize::from(g.size));
                if i + 1 != segs.len() {
                    assert_eq!(
                        q.payload.len(),
                        usize::from(g.size),
                        "only the last is short"
                    );
                    assert_eq!(q.h.flags & (FIN | PSH), 0);
                }
                rebuilt.extend_from_slice(&q.payload);
            }
            assert_eq!(rebuilt, p.payload);
            assert!(segs.len() >= 2);
            segs.len()
        }
    }
}

/// Writes `total` bytes, drains with `c.caps` and acknowledges every round after `rtt`.
fn pump(c: &mut Conn, total: usize, rtt: Duration) -> Bulk {
    let data = pattern(total, 3);
    let mut written = 0;
    let mut b = Bulk {
        received: Vec::new(),
        packets: 0,
        tso_packets: 0,
        max_segs: 0,
        max_payload: 0,
        first_tso: None,
    };
    for _ in 0..20_000 {
        if written < total {
            match c.stack.tcp_write(c.id, &data[written..]) {
                Ok(n) => written += n,
                Err(StreamError::WouldBlock) => {}
                Err(e) => panic!("{e:?}"),
            }
        }
        c.stack.handle_timeout(c.now);
        let base = c.snd;
        let mut got = 0usize;
        let stats = c.stack.tcp_stats(c.id).unwrap();
        for (t, p) in c.drain() {
            if p.payload.is_empty() {
                continue;
            }
            assert_eq!(
                p.h.seq,
                base.wrapping_add(got as u32),
                "packets leave in sequence"
            );
            let segs = check_packet(&t, &p);
            b.packets += 1;
            // The first flight leaves before any RTT sample exists and so is not paced.
            if let Some(srtt) = stats.srtt {
                // Two milliseconds at no more than twice cwnd/srtt, and never below two segments.
                let rate = u128::from(stats.cwnd) * 2 * 1_000_000_000 / srtt.as_nanos().max(1);
                let burst = (rate * 2_000_000 / 1_000_000_000) as usize;
                assert!(
                    p.payload.len() <= burst.max(2 * 1368),
                    "{} bytes at srtt {srtt:?} cwnd {}",
                    p.payload.len(),
                    stats.cwnd
                );
                b.max_payload = b.max_payload.max(p.payload.len());
            }
            if t.gso.is_some() {
                b.tso_packets += 1;
                b.max_segs = b.max_segs.max(segs);
                b.first_tso.get_or_insert((t, p.clone()));
            }
            got += p.payload.len();
            b.received.extend_from_slice(&p.payload);
            c.echo(&p);
        }
        c.now += rtt;
        if got > 0 {
            c.ack_to(base.wrapping_add(got as u32), &[]);
        }
        if b.received.len() == total {
            break;
        }
    }
    assert_eq!(b.received.len(), total, "everything was delivered");
    assert!(b.received == data, "the byte stream is intact");
    b
}

fn all(c: &mut Conn) {
    c.caps = TxCaps::ALL;
}

#[test]
fn tso_packets_carry_many_mss_segments_behind_one_header_and_a_pseudo_checksum() {
    let mut c = Conn::new(transparent());
    all(&mut c);
    let b = pump(&mut c, 3 << 20, ms(1));
    assert!(b.tso_packets > 0);
    assert!(
        b.max_segs >= 40,
        "a fast path fills 64 KiB: {} segments",
        b.max_segs
    );
    let (t, p) = b.first_tso.unwrap();
    let g = t.gso.unwrap();
    assert_eq!(g.size, 1368, "gso_size is the payload per segment");
    assert_eq!(usize::from(g.hdr_len), 20 + 32);
    assert!(p.raw.len() <= 65535);
    let stats = c.stack.stats();
    assert!(
        stats.tx_packets < (3 << 20) / 1368 / 4,
        "far fewer packets than segments: {}",
        stats.tx_packets
    );
    assert_eq!(c.stack.tcp_stats(c.id).unwrap().retrans_segments, 0);
}

#[test]
fn ipv6_tso_uses_the_v6_pseudo_header() {
    let mut c = Conn::with_addrs(transparent(), CLIENT6, DST6);
    all(&mut c);
    let b = pump(&mut c, 1 << 20, ms(1));
    let (t, p) = b.first_tso.expect("a v6 TSO packet");
    assert_eq!(p.ip_len, 40);
    assert_eq!(
        t.csum,
        TxCsum::Partial {
            start: 40,
            offset: 16
        }
    );
    assert!(p.raw.len() <= 65535);
}

#[test]
fn a_cap_for_the_other_family_does_not_enable_tso() {
    let mut c = Conn::new(transparent());
    c.caps = TxCaps {
        tso6: true,
        uso4: true,
        ..TxCaps::NONE
    };
    let b = pump(&mut c, 1 << 20, ms(1));
    assert_eq!(b.tso_packets, 0);
}

#[test]
fn caps_off_is_byte_identical_to_poll_transmit() {
    // Same script twice; one drives `poll_transmit`, the other `poll_transmit_with(NONE)`.
    fn run(with: bool) -> Vec<Vec<u8>> {
        let mut c = Conn::new(transparent());
        let data = pattern(600_000, 11);
        let mut written = 0;
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 70_000];
        let mut acked = c.snd;
        for _ in 0..4000 {
            if written < data.len() {
                match c.stack.tcp_write(c.id, &data[written..]) {
                    Ok(n) => written += n,
                    Err(StreamError::WouldBlock) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
            c.stack.handle_timeout(c.now);
            let mut got = 0u32;
            loop {
                let n = if with {
                    c.stack
                        .poll_transmit_with(c.now, &mut buf, TxCaps::NONE)
                        .map(|t| {
                            assert_eq!(t, plain(t.len, Some(c.id)));
                            t.len
                        })
                } else {
                    c.stack.poll_transmit(c.now, &mut buf)
                };
                let Some(n) = n else { break };
                let p = decode(&buf[..n]);
                got += p.payload.len() as u32;
                c.echo(&p);
                seen.push(buf[..n].to_vec());
            }
            c.now += ms(20);
            if got > 0 {
                acked = acked.wrapping_add(got);
                c.ack_to(acked, &[]);
            }
            if written == data.len() && got == 0 {
                break;
            }
        }
        seen
    }
    let (a, b) = (run(false), run(true));
    assert!(a.len() > 400);
    assert_eq!(a, b);
}

#[test]
fn the_first_flight_is_the_same_bytes_with_and_without_tso() {
    let flight = |caps: TxCaps| {
        let mut c = Conn::new(transparent());
        c.caps = caps;
        c.stack.tcp_write(c.id, &pattern(200_000, 1)).unwrap();
        let out = c.drain();
        let bytes: usize = out.iter().map(|(_, p)| p.payload.len()).sum();
        (bytes, out.len())
    };
    let (plain, plain_packets) = flight(TxCaps::NONE);
    let (tso, tso_packets) = flight(TxCaps::ALL);
    assert_eq!(
        plain, tso,
        "TSO changes packaging, not what the windows allow"
    );
    assert!(plain_packets >= 10 && tso_packets < plain_packets);
}

#[test]
fn the_receive_window_cuts_a_tso_packet_at_the_byte() {
    let mut c = Conn::new(transparent());
    all(&mut c);
    c.window = 20; // 20 << 7 = 2560 bytes
    c.client_ack(&[]);
    c.stack.tcp_write(c.id, &pattern(100_000, 2)).unwrap();
    let out = c.drain();
    let total: usize = out.iter().map(|(_, p)| p.payload.len()).sum();
    assert_eq!(total, 2560);
    assert_eq!(out.len(), 1);
    assert_eq!(
        check_packet(&out[0].0, &out[0].1),
        2,
        "one full and one short segment"
    );
    assert_eq!(out[0].1.payload.len(), 2560);
}

#[test]
fn the_pacing_burst_is_two_milliseconds_at_the_pacing_rate() {
    // A slow, long path: the two-millisecond bucket limits the burst to far fewer segments than
    // on the fast path, even as its congestion window grows. `pump` checks the bound per packet.
    let mut c = Conn::new(transparent());
    all(&mut c);
    let slow = pump(&mut c, 600_000, ms(100));
    let cap = 1368;
    assert!(slow.packets > 80, "{}", slow.packets);
    // A fast one takes whole TSO packets.
    let mut c = Conn::new(transparent());
    all(&mut c);
    let b = pump(&mut c, 3 << 20, ms(1));
    assert!(b.max_payload > 30 * cap);
    assert!(slow.max_payload < 10 * cap, "{}", slow.max_payload);
}

#[test]
fn partial_acks_and_sack_see_one_descriptor_per_segment() {
    let mut c = Conn::new(transparent());
    all(&mut c);
    let start = c.snd;
    c.stack
        .tcp_write(c.id, &pattern(8 * 1368 + 500, 4))
        .unwrap();
    let out = c.drain();
    assert_eq!(out.len(), 1, "one TSO packet");
    let (t, p) = &out[0];
    assert!(check_packet(t, p) >= 8);
    c.echo(p);
    let cap = 1368u32;
    let total = p.payload.len() as u32;
    assert_eq!(total, 8 * cap + 500);
    let s = c.stack.tcp_stats(c.id).unwrap();
    assert_eq!(s.outstanding_bytes, total);
    c.snd = start;
    c.now += ms(1);
    // Only part of descriptor 3 arrived: conservatively none is SACKed.
    c.client_ack(&[(start + 3 * cap + 100, start + 4 * cap - 100)]);
    assert_eq!(c.stack.tcp_stats(c.id).unwrap().sacked_bytes, 0);
    // A range spanning three descriptors covers only the middle one completely.
    c.client_ack(&[(start + 3 * cap + 100, start + 6 * cap - 100)]);
    assert_eq!(c.stack.tcp_stats(c.id).unwrap().sacked_bytes, cap);
    // Segments 3 and 4 arrive: exactly two descriptors in total are now SACKed.
    c.client_ack(&[(start + 3 * cap, start + 5 * cap)]);
    let s = c.stack.tcp_stats(c.id).unwrap();
    assert_eq!(s.sacked_bytes, 2 * cap);
    assert_eq!(s.outstanding_bytes, total);
    // A cumulative ACK in the middle of a segment frees only what it covers.
    c.ack_to(start + cap + 100, &[]);
    let s = c.stack.tcp_stats(c.id).unwrap();
    assert_eq!(s.outstanding_bytes, total - cap - 100);
    assert_eq!(s.sacked_bytes, 2 * cap);
    // Everything acknowledged: nothing is left in flight.
    c.ack_to(start + total, &[]);
    let s = c.stack.tcp_stats(c.id).unwrap();
    assert_eq!((s.outstanding_bytes, s.sacked_bytes), (0, 0));
}

#[test]
fn a_run_of_lost_segments_is_retransmitted_as_one_tso_packet() {
    let mut c = Conn::new(transparent());
    all(&mut c);
    // Open the window first so a big flight and a big recovery allowance exist.
    pump(&mut c, 1 << 20, ms(1));
    let start = c.snd;
    let data = pattern(60_000, 21);
    let mut off = 0;
    while off < data.len() {
        off += c.stack.tcp_write(c.id, &data[off..]).unwrap();
    }
    c.now += ms(1);
    let out = c.drain();
    let flight: usize = out.iter().map(|(_, p)| p.payload.len()).sum();
    assert!(flight > 20 * 1368);
    for (_, p) in &out {
        c.echo(p);
    }
    let cap = 1368u32;
    // The first 12 segments are lost; everything after arrives.
    c.snd = start;
    c.now += ms(1);
    let hole = 12 * cap;
    c.client_ack(&[(start + hole, start + flight as u32)]);
    c.now += ms(10);
    c.stack.handle_timeout(c.now);
    let rtx = c.drain();
    let sent: usize = rtx.iter().map(|(_, p)| p.payload.len()).sum();
    assert!(sent > 0, "the lost run is retransmitted");
    let mut covered = 0;
    let mut tso = 0;
    for (t, p) in &rtx {
        assert_eq!(p.h.seq, start.wrapping_add(covered as u32));
        assert_eq!(
            p.payload,
            data_at(&data, &out, start, p.h.seq, p.payload.len()),
            "retransmitted bytes are the originals"
        );
        if check_packet(t, p) > 1 {
            tso += 1;
        }
        covered += p.payload.len();
    }
    assert!(
        tso >= 1,
        "the run goes out as a TSO packet: {covered} bytes"
    );
    let s = c.stack.tcp_stats(c.id).unwrap();
    assert_eq!(s.retrans_bytes as usize, covered);
    assert_eq!(s.retrans_segments as usize, covered.div_ceil(cap as usize));
    assert!(covered as u32 <= hole);
}

/// The original bytes of the stream at `seq`, from the first flight `out`.
fn data_at(_data: &[u8], out: &[(Transmit, Pkt)], start: u32, seq: u32, len: usize) -> Vec<u8> {
    let mut stream = Vec::new();
    for (_, p) in out {
        stream.extend_from_slice(&p.payload);
    }
    let o = seq.wrapping_sub(start) as usize;
    stream[o..o + len].to_vec()
}

#[test]
fn fin_rides_on_the_last_segment_of_a_tso_packet() {
    let mut c = Conn::new(transparent());
    all(&mut c);
    let start = c.snd;
    c.stack.tcp_write(c.id, &pattern(5000, 8)).unwrap();
    c.stack.tcp_shutdown(c.id).unwrap();
    let out = c.drain();
    assert_eq!(out.len(), 1);
    let (t, p) = &out[0];
    assert_eq!(check_packet(t, p), 4);
    assert!(
        p.h.flags & FIN != 0,
        "the header carries FIN; the kernel keeps it on the last"
    );
    assert!(p.h.flags & PSH != 0);
    assert_eq!(p.payload.len(), 5000);
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::FinWait1));
    c.now += ms(1);
    c.ack_to(start + 5001, &[]);
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::FinWait2));
}

#[test]
fn a_small_output_buffer_degrades_to_plain_packets() {
    let mut c = Conn::new(transparent());
    c.stack.tcp_write(c.id, &pattern(50_000, 6)).unwrap();
    let mut buf = vec![0u8; 3000];
    let mut got = Vec::new();
    while let Some(t) = c.stack.poll_transmit_with(c.now, &mut buf, TxCaps::ALL) {
        let p = decode(&buf[..t.len]);
        assert!(t.len <= 3000);
        if p.payload.len() > 1368 {
            assert!(t.gso.is_some());
            check_packet(&t, &p);
        }
        got.extend_from_slice(&p.payload);
    }
    assert_eq!(got, pattern(50_000, 6)[..got.len()]);
    assert!(got.len() > 10_000);
    // A buffer that cannot hold one MTU packet still blocks, as before.
    let mut tiny = vec![0u8; 500];
    assert_eq!(
        c.stack.poll_transmit_with(c.now, &mut tiny, TxCaps::ALL),
        None
    );
}

fn endpoint_client() -> (Stack, honk_netstack::FlowId, Instant, u32, u32) {
    let t0 = Instant::now();
    let mut cfg = Config::new([5; 32]);
    cfg.local_v4 = Some("10.0.0.2".parse().unwrap());
    let mut s = Stack::new(cfg, t0);
    let remote = addr(DST);
    let id = s.tcp_connect(t0, remote).unwrap();
    let mut buf = [0u8; 2000];
    let n = s.poll_transmit(t0, &mut buf).unwrap();
    let syn = decode(&buf[..n]);
    let synack = build(
        remote,
        syn.src,
        7000,
        syn.h.seq.wrapping_add(1),
        tcp::SYN | ACK,
        opts_syn(1460),
        &[],
    );
    assert_eq!(s.receive(t0 + ms(2), &synack), Rx::Consumed);
    (s, id, t0 + ms(2), 7001, syn.h.seq.wrapping_add(1))
}

#[test]
fn an_endpoint_stack_ignores_tx_caps() {
    let (mut s, id, now, _, _) = endpoint_client();
    s.tcp_write(id, &pattern(100_000, 1)).unwrap();
    let mut buf = vec![0u8; 70_000];
    let mut n = 0;
    while let Some(t) = s.poll_transmit_with(now, &mut buf, TxCaps::ALL) {
        assert_eq!(
            t,
            plain(t.len, Some(id)),
            "endpoint packets are complete and single"
        );
        assert!(t.len <= 1420);
        n += 1;
    }
    assert!(n >= 10);
}

#[test]
fn uso_sends_one_packet_that_splits_back_into_the_datagrams() {
    let mut s = Stack::new(transparent(), Instant::now());
    let (src, dst) = (addr(DST), addr(CLIENT));
    for (src, dst) in [(src, dst), (addr(DST6), addr(CLIENT6))] {
        let payload = pattern(20 * 1000 + 123, 5);
        let mut out = vec![0u8; 70_000];
        let t = s
            .udp_send_gso_from((src, dst), &payload, 1000, TxCaps::ALL, &mut out)
            .unwrap();
        let g = t.gso.unwrap();
        assert_eq!((g.kind, g.size), (GsoKind::UdpL4, 1000));
        let ip = wire::parse_ip(&out[..t.len]).unwrap();
        assert_eq!(ip.proto, PROTO_UDP);
        assert_eq!(usize::from(g.hdr_len), ip.payload.start + 8);
        assert_eq!(
            t.csum,
            TxCsum::Partial {
                start: ip.payload.start as u16,
                offset: 6
            }
        );
        let udp_len = ip.payload.len();
        assert_eq!(udp_len, 8 + payload.len());
        let field = u16::from_be_bytes([out[ip.payload.start + 6], out[ip.payload.start + 7]]);
        assert_eq!(field, pseudo_seed(src.ip(), dst.ip(), PROTO_UDP, udp_len));
        // The device completes the checksum of the whole packet.
        let mut whole = out[..t.len].to_vec();
        complete_checksum(&mut whole, ip.payload.start, 6);
        assert!(wire::udp::verify_checksum(
            src.ip(),
            dst.ip(),
            &whole[ip.payload.start..]
        ));
        // Each datagram the device cuts is a valid packet on its own, boundaries intact.
        let mut seen = Vec::new();
        for chunk in payload.chunks(1000) {
            let mut b = vec![0u8; chunk.len() + 80];
            let n = wire::udp::emit_packet(&mut b, src, dst, chunk).unwrap();
            let q = wire::parse_ip(&b[..n]).unwrap();
            assert!(wire::udp::verify_checksum(
                src.ip(),
                dst.ip(),
                &b[q.payload.clone()]
            ));
            seen.push(chunk.len());
        }
        assert_eq!(seen.len(), 21);
        assert_eq!(seen.last(), Some(&123));
    }
    assert_eq!(s.stats().tx_packets, 2);
}

#[test]
fn uso_errors_consume_nothing_and_respect_the_limits() {
    let mut s = Stack::new(transparent(), Instant::now());
    let (src, dst) = (addr(DST), addr(CLIENT));
    let mut out = vec![0u8; 70_000];
    let big = pattern(10_000, 1);
    let try_send = |s: &mut Stack, size: u16, caps: TxCaps, payload: &[u8], out: &mut [u8]| {
        s.udp_send_gso_from((src, dst), payload, size, caps, out)
    };
    assert_eq!(
        try_send(&mut s, 1000, TxCaps::NONE, &big, &mut out),
        Err(UdpError::Offload)
    );
    assert_eq!(
        try_send(
            &mut s,
            1000,
            TxCaps {
                uso6: true,
                ..TxCaps::NONE
            },
            &big,
            &mut out
        ),
        Err(UdpError::Offload),
        "the family's own capability is required"
    );
    // 65 datagrams of 100 bytes: over the portable limit of 64.
    assert_eq!(
        try_send(&mut s, 100, TxCaps::ALL, &pattern(6500, 1), &mut out),
        Err(UdpError::TooLarge)
    );
    assert!(try_send(&mut s, 100, TxCaps::ALL, &pattern(6400, 1), &mut out).is_ok());
    // A datagram that does not fit the MTU with its headers.
    assert_eq!(
        try_send(&mut s, 1400, TxCaps::ALL, &big, &mut out),
        Err(UdpError::TooLarge)
    );
    assert_eq!(
        try_send(&mut s, 0, TxCaps::ALL, &big, &mut out),
        Err(UdpError::TooLarge)
    );
    assert_eq!(
        try_send(&mut s, 1000, TxCaps::ALL, &big, &mut out[..5000]),
        Err(UdpError::BufferTooSmall)
    );
    assert_eq!(
        s.udp_send_gso_from((src, addr(CLIENT6)), &big, 1000, TxCaps::ALL, &mut out),
        Err(UdpError::FamilyMismatch)
    );
    // One datagram's worth is an ordinary send.
    let t = try_send(&mut s, 1000, TxCaps::NONE, &big[..900], &mut out).unwrap();
    assert_eq!(t, plain(t.len, None));
    assert_eq!(s.stats().tx_packets, 2);
    // An endpoint stack never takes offload.
    let mut e = Stack::new(Config::new([1; 32]), Instant::now());
    assert_eq!(
        e.udp_send_gso_from((src, dst), &big, 1000, TxCaps::ALL, &mut out),
        Err(UdpError::Offload)
    );
}

#[test]
fn max_mss_caps_each_segment_not_the_super_packet() {
    let opts = honk_netstack::AcceptOpts {
        max_mss: Some(600),
        ..Default::default()
    };
    let mut c = Conn::with_opts(transparent(), opts);
    all(&mut c);
    c.stack.tcp_write(c.id, &pattern(6000, 3)).unwrap();
    let out = c.drain();
    assert_eq!(out.len(), 1);
    let (tx, packet) = &out[0];
    let gso = tx
        .gso
        .expect("multiple path-sized segments behind one header");
    assert_eq!(gso.size, 588, "MSS minus timestamp options");
    assert!(packet.payload.len() > 600);
    check_packet(tx, packet);
    for segment in tso_segments(tx, packet) {
        let segment = decode(&segment);
        assert!(segment.payload.len() <= 588);
        assert!(segment.raw.len() <= 600 + 20 + 20);
    }
}

#[test]
fn plain_udp_fragments_never_adopt_offload_metadata() {
    for (src, dst) in [(addr(DST), addr(CLIENT)), (addr(DST6), addr(CLIENT6))] {
        let now = Instant::now();
        let mut stack = Stack::new(transparent(), now);
        let mut packet = [0; 2000];
        let first = stack
            .udp_send_from(src, dst, &pattern(5000, 17), &mut packet)
            .unwrap();
        assert!(first <= 1420);
        assert_eq!(
            wire::parse_ip(&packet[..first]),
            Err(wire::ParseError::Fragment)
        );
        let mut fragments = 1;
        while let Some(tx) = stack.poll_transmit_with(now, &mut packet, TxCaps::ALL) {
            assert_eq!(
                tx,
                plain(tx.len, None),
                "IP fragmentation is not UDP segmentation"
            );
            assert!(tx.len <= 1420);
            assert_eq!(
                wire::parse_ip(&packet[..tx.len]),
                Err(wire::ParseError::Fragment)
            );
            fragments += 1;
        }
        assert!(fragments >= 4);
        assert_eq!(stack.stats().tx_packets, fragments);
    }
}

#[test]
fn uso_reserves_the_ipv4_id_run_before_plain_and_fragmented_sends() {
    let now = Instant::now();
    let mut stack = Stack::new(transparent(), now);
    let pair = (addr(DST), addr(CLIENT));
    let mut packet = [0; 70_000];
    let id = |packet: &[u8]| u16::from_be_bytes([packet[4], packet[5]]);
    let data = pattern(3000, 1);
    let tx = stack
        .udp_send_gso_from(pair, &data, 1000, TxCaps::ALL, &mut packet)
        .unwrap();
    let first = id(&packet[..tx.len]);
    // A rejected super-packet must not consume IDs.
    assert_eq!(
        stack.udp_send_gso_from(pair, &data, 1000, TxCaps::ALL, &mut packet[..100]),
        Err(UdpError::BufferTooSmall)
    );
    let n = stack
        .udp_send_from(pair.0, pair.1, b"plain", &mut packet)
        .unwrap();
    assert_eq!(id(&packet[..n]), first.wrapping_add(3));
    let tx = stack
        .udp_send_gso_from(pair, &data[..2000], 1000, TxCaps::ALL, &mut packet)
        .unwrap();
    assert_eq!(id(&packet[..tx.len]), first.wrapping_add(4));
    let n = stack
        .udp_send_from(pair.0, pair.1, &data, &mut packet)
        .unwrap();
    assert_eq!(id(&packet[..n]), first.wrapping_add(6));
    while let Some(tx) = stack.poll_transmit_with(now, &mut packet, TxCaps::ALL) {
        assert_eq!(id(&packet[..tx.len]), first.wrapping_add(6));
    }
    let n = stack
        .udp_send_from(pair.0, pair.1, b"next", &mut packet)
        .unwrap();
    assert_eq!(id(&packet[..n]), first.wrapping_add(7));
}
