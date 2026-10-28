//! Offload metadata on receive: checksum provenance (accepted only in transparent mode), TCP
//! super-packets (integrity, ACK cadence, OOO/SACK, PAWS) and UDP USO super-packets.

mod offload_common;

use std::time::Instant;

use honk_netstack::wire;
use honk_netstack::wire::tcp::{self, ACK, PSH};
use honk_netstack::{Config, Csum, DropReason, GsoKind, GsoRx, Rx, RxMeta, Stack, StreamError};
use offload_common::*;

const MSS: usize = 1368;

fn valid() -> RxMeta {
    RxMeta {
        csum: Csum::Valid,
        gso: None,
    }
}

/// Corrupts the TCP/UDP checksum field without touching anything the IP header covers.
fn corrupt_l4(mut p: Vec<u8>, field: usize) -> Vec<u8> {
    let ihl = wire::parse_ip(&p).unwrap().payload.start;
    p[ihl + field] ^= 0x55;
    p
}

fn read_all(c: &mut Conn) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 70_000];
    loop {
        match c.stack.tcp_read(c.id, &mut buf) {
            Ok(n) if n > 0 => out.extend_from_slice(&buf[..n]),
            Err(StreamError::WouldBlock) | Ok(_) => return out,
            Err(e) => panic!("{e:?}"),
        }
    }
}

/// `n` consecutive full segments as client packets (advancing the client's sequence).
fn segments(c: &mut Conn, data: &[u8], size: usize) -> Vec<Vec<u8>> {
    data.chunks(size)
        .map(|d| c.client_pkt(ACK, d, &[]))
        .collect()
}

fn acks(c: &mut Conn) -> Vec<Pkt> {
    c.drain().into_iter().map(|(_, p)| p).collect()
}

/// Sends single segments until the initial quick-ACK burst is spent, draining the ACKs.
fn spend_quickack(c: &mut Conn) {
    for i in 0..20 {
        let p = c.client_pkt(ACK, &pattern(MSS, i), &[]);
        assert_eq!(c.stack.receive(c.now, &p), Rx::Consumed);
        acks(c);
        c.now += ms(1);
    }
    read_all(c);
    // Reading opened the window enough to owe an update; get it out of the way.
    acks(c);
    c.now += ms(1);
}

#[test]
fn a_tcp_super_packet_is_one_contiguous_segment_with_intact_data_and_one_ack() {
    let mut c = Conn::new(transparent());
    let data = pattern(40 * MSS + 17, 7);
    let segs = segments(&mut c, &data, MSS);
    let (pkt, meta) = gro(&segs, MSS as u16);
    assert_eq!(c.stack.receive_with(c.now, &pkt, meta), Rx::Consumed);
    let out = acks(&mut c);
    assert_eq!(out.len(), 1, "one ACK for the whole run, not one per frame");
    assert_eq!(out[0].h.ack, c.seq, "it acknowledges everything");
    assert_eq!(out[0].h.flags & ACK, ACK);
    c.now += ms(1);
    let got = read_all(&mut c);
    assert!(
        got == data,
        "the ring holds exactly the super-packet's bytes"
    );
    // The window update after the read is the only other thing owed.
    for p in acks(&mut c) {
        assert!(p.payload.is_empty());
    }
}

#[test]
fn ack_cadence_counts_full_frames_of_a_super_packet() {
    let mut c = Conn::new(transparent());
    spend_quickack(&mut c);
    let one = |c: &mut Conn| {
        let p = c.client_pkt(ACK, &pattern(MSS, 1), &[]);
        c.stack.receive(c.now, &p)
    };
    // A lone full frame is acknowledged late (delayed ACK), a super-packet of one frame too.
    assert_eq!(one(&mut c), Rx::Consumed);
    assert!(acks(&mut c).is_empty(), "the first full frame waits");
    c.now += ms(41);
    c.stack.handle_timeout(c.now);
    assert_eq!(acks(&mut c).len(), 1, "the delayed-ACK timer fires");

    let segs = segments(&mut c, &pattern(MSS, 2), MSS);
    let (pkt, meta) = gro(&segs, MSS as u16);
    c.stack.receive_with(c.now, &pkt, meta);
    assert!(
        acks(&mut c).is_empty(),
        "ceil(len/size) = 1 frame: still delayed"
    );
    c.now += ms(41);
    c.stack.handle_timeout(c.now);
    assert_eq!(acks(&mut c).len(), 1);

    // Two frames are two full segments: acknowledge now, once, for both.
    let segs = segments(&mut c, &pattern(2 * MSS, 3), MSS);
    let (pkt, meta) = gro(&segs, MSS as u16);
    c.stack.receive_with(c.now, &pkt, meta);
    let out = acks(&mut c);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].h.ack, c.seq);

    // A short second frame still counts as a frame: ceil(1378 / 1368) = 2.
    let segs = segments(&mut c, &pattern(MSS + 10, 3), MSS);
    let (pkt, meta) = gro(&segs, MSS as u16);
    c.stack.receive_with(c.now, &pkt, meta);
    assert_eq!(acks(&mut c).len(), 1);

    // One frame left waiting, then a super-packet: the ACK covers both.
    assert_eq!(one(&mut c), Rx::Consumed);
    assert!(acks(&mut c).is_empty());
    let segs = segments(&mut c, &pattern(3 * MSS, 4), MSS);
    let (pkt, meta) = gro(&segs, MSS as u16);
    c.stack.receive_with(c.now, &pkt, meta);
    let out = acks(&mut c);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].h.ack, c.seq);
}

#[test]
fn single_frames_are_still_acknowledged_every_second_frame() {
    // The baseline the super-packet cadence is measured against.
    let mut c = Conn::new(transparent());
    spend_quickack(&mut c);
    let mut total = 0;
    for i in 0..20 {
        let p = c.client_pkt(ACK, &pattern(MSS, i), &[]);
        c.stack.receive(c.now, &p);
        total += acks(&mut c).len();
    }
    assert_eq!(total, 10);
}

#[test]
fn out_of_order_super_packets_generate_exact_sack_blocks_and_fill_in_order() {
    let mut c = Conn::new(transparent());
    let data = pattern(30 * MSS, 9);
    let first = c.seq;
    let segs = segments(&mut c, &data, MSS);
    // Segments 0..10 are lost; 10..20 and 25..30 arrive as two super-packets.
    let (a, ma) = gro(&segs[10..20], MSS as u16);
    let (b, mb) = gro(&segs[25..30], MSS as u16);
    c.stack.receive_with(c.now, &a, ma);
    let out = acks(&mut c);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].h.ack, first, "a duplicate ACK, nothing advanced");
    let lo = first + (10 * MSS) as u32;
    assert_eq!(
        out[0].h.options.sack.as_slice(),
        &[(lo, lo + (10 * MSS) as u32)]
    );
    c.stack.receive_with(c.now, &b, mb);
    let out = acks(&mut c);
    assert_eq!(out.len(), 1);
    let blocks = out[0].h.options.sack.as_slice();
    assert_eq!(blocks.len(), 2);
    assert!(blocks.contains(&(first + (25 * MSS) as u32, first + (30 * MSS) as u32)));
    assert!(blocks.contains(&(lo, lo + (10 * MSS) as u32)));
    assert!(
        read_all(&mut c).is_empty(),
        "nothing is readable behind the hole"
    );
    // A duplicate super-packet is reported as a DSACK.
    let (a2, ma2) = gro(&segs[10..20], MSS as u16);
    c.stack.receive_with(c.now, &a2, ma2);
    let out = acks(&mut c);
    assert_eq!(
        out[0].h.options.sack.as_slice()[0],
        (lo, lo + (10 * MSS) as u32)
    );
    // The hole is filled by one more super-packet: the ACK jumps over everything held.
    let (h, mh) = gro(&segs[0..10], MSS as u16);
    c.stack.receive_with(c.now, &h, mh);
    let out = acks(&mut c);
    assert_eq!(out.last().unwrap().h.ack, first + (20 * MSS) as u32);
    let (m, mm) = gro(&segs[20..25], MSS as u16);
    c.stack.receive_with(c.now, &m, mm);
    let out = acks(&mut c);
    assert_eq!(out.last().unwrap().h.ack, first + (30 * MSS) as u32);
    assert!(read_all(&mut c) == data);
}

#[test]
fn paws_and_timestamps_see_a_super_packet_as_one_segment() {
    let mut c = Conn::new(transparent());
    let before = c.seq;
    let segs = segments(&mut c, &pattern(8 * MSS, 1), MSS);
    // A super-packet older than the last accepted timestamp is rejected as a whole.
    let (mut old, meta) = gro(&segs, MSS as u16);
    let ihl = 20;
    let ts_off = ihl + 20 + 4; // NOP NOP kind len, then TSval
    let stale = (c.ts - 100).to_be_bytes();
    old[ts_off..ts_off + 4].copy_from_slice(&stale);
    // The corrupted option bytes break the IP-independent checksum, which the metadata vouches for.
    assert_eq!(c.stack.receive_with(c.now, &old, meta), Rx::Consumed);
    assert!(read_all(&mut c).is_empty(), "PAWS dropped it");
    // A fresh one is accepted and its first timestamp is remembered.
    let (new, meta) = gro(&segs, MSS as u16);
    c.stack.receive_with(c.now, &new, meta);
    assert_eq!(read_all(&mut c).len(), 8 * MSS);
    let out = acks(&mut c);
    assert_eq!(out.last().unwrap().h.ack, before + (8 * MSS) as u32);
    let echoed = out.last().unwrap().h.options.timestamps.unwrap().1;
    assert_eq!(echoed, decode(&segs[0]).h.options.timestamps.unwrap().0);
}

#[test]
fn a_super_packet_larger_than_the_window_is_trimmed_like_any_segment() {
    let mut cfg = transparent();
    cfg.tcp_rcv_buf_max = 16 * 1024;
    let mut c = Conn::new(cfg);
    let window = c.stack.tcp_stats(c.id).unwrap().receive_window as usize;
    let segs = segments(&mut c, &pattern(40 * MSS, 5), MSS);
    let (pkt, meta) = gro(&segs, MSS as u16);
    c.stack.receive_with(c.now, &pkt, meta);
    let got = read_all(&mut c);
    assert!(
        got.len() <= window.max(1) && !got.is_empty(),
        "{} vs {window}",
        got.len()
    );
    assert_eq!(got, pattern(40 * MSS, 5)[..got.len()]);
}

#[test]
fn offload_metadata_is_refused_by_an_endpoint_stack() {
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
    let now = t0 + ms(3);
    let data = pattern(100, 1);
    let good = build(
        remote,
        syn.src,
        7001,
        syn.h.seq.wrapping_add(1),
        ACK | PSH,
        tcp::Options {
            timestamps: Some((9000, 0)),
            ..Default::default()
        },
        &data,
    );
    let bad = corrupt_l4(good.clone(), 16);
    let start = wire::parse_ip(&good).unwrap().payload.start as u16;
    let unsupported = Rx::Dropped(DropReason::Unsupported);
    for meta in [
        valid(),
        RxMeta {
            csum: Csum::Partial { start, offset: 16 },
            gso: None,
        },
        RxMeta {
            csum: Csum::Verify,
            gso: Some(GsoRx {
                kind: GsoKind::Tcp,
                size: 50,
            }),
        },
    ] {
        assert_eq!(s.receive_with(now, &bad, meta), unsupported);
        assert_eq!(s.receive_with(now, &good, meta), unsupported);
    }
    let mut out = [0u8; 200];
    assert_eq!(
        s.tcp_read(id, &mut out),
        Err(StreamError::WouldBlock),
        "nothing reached the flow"
    );
    // The plain metadata keeps the always-verify rule: a corrupt checksum is dropped.
    assert_eq!(
        s.receive_with(now, &bad, RxMeta::VERIFY),
        Rx::Dropped(DropReason::Checksum)
    );
    assert_eq!(s.receive(now, &bad), Rx::Dropped(DropReason::Checksum));
    assert_eq!(s.receive_with(now, &good, RxMeta::default()), Rx::Consumed);
    assert_eq!(s.tcp_read(id, &mut out), Ok(100));
    let stats = s.stats();
    assert_eq!(stats.drops[DropReason::Unsupported as usize], 6);
}

#[test]
fn a_transparent_stack_takes_the_drivers_word_for_tcp_and_udp_checksums() {
    let mut c = Conn::new(transparent());
    let p = c.client_pkt(ACK, &pattern(300, 1), &[]);
    let start = wire::parse_ip(&p).unwrap().payload.start;
    let bad = corrupt_l4(p.clone(), 16);
    assert_eq!(
        c.stack.receive_with(c.now, &bad, RxMeta::VERIFY),
        Rx::Dropped(DropReason::Checksum)
    );
    assert!(read_all(&mut c).is_empty());
    assert_eq!(c.stack.receive_with(c.now, &bad, valid()), Rx::Consumed);
    assert_eq!(read_all(&mut c).len(), 300);
    // CHECKSUM_PARTIAL: the field is only a seed and is not looked at.
    let p2 = c.client_pkt(ACK, &pattern(300, 2), &[]);
    let seeded = corrupt_l4(p2, 16);
    let partial = |start: usize, offset: u16| RxMeta {
        csum: Csum::Partial {
            start: start as u16,
            offset,
        },
        gso: None,
    };
    // A claim that does not point at the L4 checksum field is a lie about this packet.
    for (s, o) in [
        (start + 4, 16),
        (start - 4, 16),
        (start, 6),
        (start, 17),
        (0, 0),
    ] {
        assert_eq!(
            c.stack.receive_with(c.now, &seeded, partial(s, o)),
            Rx::Dropped(DropReason::Malformed),
            "start {s} offset {o}"
        );
    }
    assert!(read_all(&mut c).is_empty());
    assert_eq!(
        c.stack.receive_with(c.now, &seeded, partial(start, 16)),
        Rx::Consumed
    );
    assert_eq!(read_all(&mut c).len(), 300);

    // UDP: the checksum offset is 6.
    let (src, dst) = (addr(CLIENT), addr(DST));
    let mut b = vec![0u8; 400];
    let n = wire::udp::emit_packet(&mut b, src, dst, &pattern(200, 3)).unwrap();
    let udp = corrupt_l4(b[..n].to_vec(), 6);
    assert_eq!(
        c.stack.receive_with(c.now, &udp, RxMeta::VERIFY),
        Rx::Dropped(DropReason::Checksum)
    );
    let Rx::Transparent { payload, .. } = c.stack.receive_with(c.now, &udp, valid()) else {
        panic!("a vouched datagram is delivered")
    };
    assert_eq!(payload.len(), 200);
    assert!(matches!(
        c.stack.receive_with(c.now, &udp, partial(start, 6)),
        Rx::Transparent { .. }
    ));
    assert_eq!(
        c.stack.receive_with(c.now, &udp, partial(start, 16)),
        Rx::Dropped(DropReason::Malformed)
    );
}

#[test]
fn the_ip_header_icmp_and_reassembled_datagrams_are_always_verified() {
    let mut c = Conn::new(transparent());
    // IPv4 header checksum.
    let mut p = c.client_pkt(ACK, &pattern(50, 1), &[]);
    p[10] ^= 1;
    assert_eq!(
        c.stack.receive_with(c.now, &p, valid()),
        Rx::Dropped(DropReason::Checksum)
    );
    // ICMP.
    let original = c.client_pkt(ACK, &pattern(50, 1), &[]);
    let mut icmp = vec![0u8; 200];
    let n = wire::icmp::emit_packet_too_big(
        &mut icmp,
        addr(CLIENT).ip(),
        addr(DST).ip(),
        1000,
        &original,
    )
    .unwrap();
    let mut icmp = icmp[..n].to_vec();
    let last = icmp.len() - 1;
    icmp[last] ^= 1;
    assert_eq!(
        c.stack.receive_with(c.now, &icmp, valid()),
        Rx::Dropped(DropReason::Checksum)
    );
    // A UDP datagram reassembled from fragments is verified whatever the fragments claimed.
    let (src, dst) = (addr(CLIENT), addr(DST));
    let mut b = vec![0u8; 3000];
    let n = wire::udp::emit_packet(&mut b, src, dst, &pattern(2000, 3)).unwrap();
    let whole = corrupt_l4(b[..n].to_vec(), 6);
    let frags = fragment_v4(&whole, 1200);
    assert_eq!(
        c.stack.receive_with(c.now, &frags[0], valid()),
        Rx::Consumed
    );
    assert_eq!(
        c.stack.receive_with(c.now, &frags[1], valid()),
        Rx::Dropped(DropReason::Checksum)
    );
    // The same fragments with a good checksum are delivered.
    let good = b[..n].to_vec();
    let frags = fragment_v4(&good, 1200);
    assert_eq!(
        c.stack.receive_with(c.now, &frags[0], valid()),
        Rx::Consumed
    );
    assert!(matches!(
        c.stack.receive_with(c.now, &frags[1], valid()),
        Rx::TransparentOwned { .. }
    ));
}

/// Cuts an IPv4 packet's payload into two fragments at `at` bytes of payload.
fn fragment_v4(packet: &[u8], at: usize) -> [Vec<u8>; 2] {
    assert_eq!(at % 8, 0);
    let cut = |range: std::ops::Range<usize>, more: bool| {
        let mut f = packet[..20].to_vec();
        f.extend_from_slice(&packet[20 + range.start..20 + range.end]);
        let total = f.len() as u16;
        f[2..4].copy_from_slice(&total.to_be_bytes());
        let field = (range.start / 8) as u16 | if more { 0x2000 } else { 0 };
        f[6..8].copy_from_slice(&field.to_be_bytes());
        f[10..12].copy_from_slice(&[0, 0]);
        let sum = !sum16(&f[..20], 0);
        f[10..12].copy_from_slice(&sum.to_be_bytes());
        f
    };
    let end = packet.len() - 20;
    [cut(0..at, true), cut(at..end, false)]
}

fn udp_super(count: usize, size: usize, last: usize) -> (Vec<u8>, Vec<u8>) {
    let (src, dst) = (addr(CLIENT), addr(DST));
    let payload = pattern((count - 1) * size + last, 4);
    let mut b = vec![0u8; payload.len() + 80];
    let n = wire::udp::emit_packet(&mut b, src, dst, &payload).unwrap();
    b.truncate(n);
    (b, payload)
}

fn uso(size: u16) -> GsoRx {
    GsoRx {
        kind: GsoKind::UdpL4,
        size,
    }
}

#[test]
fn a_uso_super_packet_splits_into_datagrams_by_size() {
    let mut c = Conn::new(transparent());
    let (pkt, payload) = udp_super(6, 1000, 123);
    let start = wire::parse_ip(&pkt).unwrap().payload.start;
    for csum in [
        Csum::Verify,
        Csum::Valid,
        Csum::Partial {
            start: start as u16,
            offset: 6,
        },
    ] {
        let meta = RxMeta {
            csum,
            gso: Some(uso(1000)),
        };
        // Verify needs a real checksum, which `emit_packet` wrote; the others do not look.
        let Rx::TransparentSplit {
            src,
            dst,
            dscp,
            payload: range,
            size,
        } = c.stack.receive_with(c.now, &pkt, meta)
        else {
            panic!("expected a split for {csum:?}")
        };
        assert_eq!((src, dst), (addr(CLIENT), addr(DST)));
        assert_eq!(dscp, 0);
        assert_eq!(size, 1000);
        let chunks: Vec<&[u8]> = pkt[range].chunks(usize::from(size)).collect();
        assert_eq!(chunks.len(), 6);
        assert_eq!(
            chunks.iter().map(|c| c.len()).collect::<Vec<_>>(),
            [1000, 1000, 1000, 1000, 1000, 123]
        );
        assert_eq!(chunks.concat(), payload, "boundaries are preserved");
    }
    // One datagram's worth is an ordinary datagram, whatever the metadata says.
    let (one, p1) = udp_super(1, 1000, 700);
    let meta = RxMeta {
        csum: Csum::Verify,
        gso: Some(uso(1000)),
    };
    let Rx::Transparent { payload, .. } = c.stack.receive_with(c.now, &one, meta) else {
        panic!("a single datagram")
    };
    assert_eq!(one[payload], p1[..]);
    // A bad checksum with Verify is still dropped.
    let bad = corrupt_l4(pkt.clone(), 6);
    let meta = RxMeta {
        csum: Csum::Verify,
        gso: Some(uso(1000)),
    };
    assert_eq!(
        c.stack.receive_with(c.now, &bad, meta),
        Rx::Dropped(DropReason::Checksum)
    );
}

#[test]
fn contradictory_gso_metadata_is_malformed() {
    let mut c = Conn::new(transparent());
    let malformed = Rx::Dropped(DropReason::Malformed);
    let (udp, _) = udp_super(4, 500, 500);
    let with = |gso: GsoRx| RxMeta {
        csum: Csum::Valid,
        gso: Some(gso),
    };
    // Size 0, the wrong protocol, and more than the kernel's 128 segments.
    assert_eq!(c.stack.receive_with(c.now, &udp, with(uso(0))), malformed);
    let tcp_kind = GsoRx {
        kind: GsoKind::Tcp,
        size: 500,
    };
    assert_eq!(c.stack.receive_with(c.now, &udp, with(tcp_kind)), malformed);
    let (many, _) = udp_super(130, 10, 10);
    assert_eq!(c.stack.receive_with(c.now, &many, with(uso(10))), malformed);
    let (ok, _) = udp_super(128, 10, 10);
    assert!(matches!(
        c.stack.receive_with(c.now, &ok, with(uso(10))),
        Rx::TransparentSplit { .. }
    ));
    let t = c.client_pkt(ACK, &pattern(100, 1), &[]);
    assert_eq!(c.stack.receive_with(c.now, &t, with(uso(50))), malformed);
    assert_eq!(
        c.stack.receive_with(
            c.now,
            &t,
            with(GsoRx {
                size: 0,
                ..tcp_kind
            })
        ),
        malformed
    );
    // Super-packet metadata on an ICMP message or a fragment has no meaning.
    let mut icmp = vec![0u8; 200];
    let n = wire::icmp::emit_packet_too_big(&mut icmp, addr(CLIENT).ip(), addr(DST).ip(), 1000, &t)
        .unwrap();
    assert_eq!(
        c.stack.receive_with(c.now, &icmp[..n], with(tcp_kind)),
        malformed
    );
    let (big, _) = udp_super(3, 800, 800);
    let frags = fragment_v4(&big, 1200);
    assert_eq!(
        c.stack.receive_with(c.now, &frags[0], with(uso(800))),
        malformed
    );
    assert_eq!(c.stack.stats().drops[DropReason::Malformed as usize], 7);
}
