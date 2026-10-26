use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use honk_netstack::wire::tcp::{self, ACK, FIN, Header, Options, RST, SYN};
use honk_netstack::{Config, FlowId, Ready, Rx, Stack, StreamError, TcpState};

fn config(v6: bool) -> Config {
    let mut cfg = Config::new([0x57; 32]);
    if v6 {
        cfg.local_v6 = Some("2001:db8:1::1".parse().unwrap());
    } else {
        cfg.local_v4 = Some(Ipv4Addr::new(192, 0, 2, 1));
    }
    cfg.max_flows = 4;
    cfg.memory_limit = 16 * 1024 * 1024;
    cfg.tcp_rcv_buf_max = 3 * 1024 * 1024;
    cfg
}

fn peer_options(timestamps: bool, sack: bool) -> Options {
    Options {
        mss: Some(1460),
        wscale: Some(3),
        sack_permitted: sack,
        timestamps: timestamps.then_some((1000, 0)),
        ..Options::default()
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

// Independent of the production parser/checksummer: output must survive a real peer.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Debug)]
struct Packet {
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: Vec<u8>,
    payload: Vec<u8>,
}

impl Packet {
    fn decode(bytes: &[u8]) -> Self {
        let (ip_len, src, dst) = match bytes[0] >> 4 {
            4 => {
                assert_eq!(bytes[0], 0x45);
                assert_eq!(usize::from(u16_at(bytes, 2)), bytes.len());
                assert_eq!(bytes[9], 6);
                assert_eq!(checksum(&bytes[..20]), 0, "IPv4 checksum");
                (
                    20,
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap())),
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).unwrap())),
                )
            }
            6 => {
                assert_eq!(usize::from(u16_at(bytes, 4)) + 40, bytes.len());
                assert_eq!(bytes[6], 6);
                (
                    40,
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap())),
                    IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&bytes[24..40]).unwrap(),
                    )),
                )
            }
            version => panic!("unexpected IP version {version}"),
        };
        let seg = &bytes[ip_len..];
        let mut pseudo = Vec::new();
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                pseudo.extend_from_slice(&s.octets());
                pseudo.extend_from_slice(&d.octets());
                pseudo.extend_from_slice(&[0, 6]);
                pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                pseudo.extend_from_slice(&s.octets());
                pseudo.extend_from_slice(&d.octets());
                pseudo.extend_from_slice(&(seg.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, 6]);
            }
            _ => unreachable!(),
        }
        pseudo.extend_from_slice(seg);
        assert_eq!(checksum(&pseudo), 0, "TCP pseudo-header checksum");
        let header_len = usize::from(seg[12] >> 4) * 4;
        assert!((20..=60).contains(&header_len));
        assert_eq!(seg[12] & 0x0f, 0, "reserved TCP bits");
        assert_eq!(u16_at(seg, 18), 0, "urgent pointer");
        Self {
            src: SocketAddr::new(src, u16_at(seg, 0)),
            dst: SocketAddr::new(dst, u16_at(seg, 2)),
            seq: u32_at(seg, 4),
            ack: u32_at(seg, 8),
            flags: seg[13],
            window: u16_at(seg, 14),
            options: seg[20..header_len].to_vec(),
            payload: seg[header_len..].to_vec(),
        }
    }

    fn option(&self, kind: u8) -> Option<&[u8]> {
        let mut at = 0;
        while at < self.options.len() {
            let k = self.options[at];
            if k == 0 {
                break;
            }
            if k == 1 {
                at += 1;
                continue;
            }
            let len = usize::from(self.options[at + 1]);
            assert!(len >= 2 && at + len <= self.options.len());
            if k == kind {
                return Some(&self.options[at + 2..at + len]);
            }
            at += len;
        }
        None
    }

    fn timestamp(&self) -> Option<(u32, u32)> {
        self.option(8).map(|b| {
            assert_eq!(b.len(), 8);
            (u32_at(b, 0), u32_at(b, 4))
        })
    }

    fn sacks(&self) -> Vec<(u32, u32)> {
        self.option(5).map_or_else(Vec::new, |b| {
            assert_eq!(b.len() % 8, 0);
            b.as_chunks::<8>()
                .0
                .iter()
                .map(|b| (u32_at(b, 0), u32_at(b, 4)))
                .collect()
        })
    }

    fn assert_tcp(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        assert_eq!((self.seq, self.ack, self.flags), (seq, ack, flags));
        assert_eq!(self.payload, payload);
    }
}

fn established_options(timestamp: Option<(u32, u32)>, sacks: &[(u32, u32)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some((val, echo)) = timestamp {
        bytes.extend_from_slice(&[1, 1, 8, 10]);
        bytes.extend_from_slice(&val.to_be_bytes());
        bytes.extend_from_slice(&echo.to_be_bytes());
    }
    if !sacks.is_empty() {
        bytes.extend_from_slice(&[1, 1, 5, (2 + sacks.len() * 8) as u8]);
        for &(left, right) in sacks {
            bytes.extend_from_slice(&left.to_be_bytes());
            bytes.extend_from_slice(&right.to_be_bytes());
        }
    }
    bytes
}

fn pull(stack: &mut Stack, now: Instant) -> Option<Packet> {
    let mut bytes = [0u8; 2000];
    stack
        .poll_transmit(now, &mut bytes)
        .map(|n| Packet::decode(&bytes[..n]))
}

struct Script {
    stack: Stack,
    id: FlowId,
    base: Instant,
    local: SocketAddr,
    peer: SocketAddr,
    syn: Packet,
    handshake: Packet,
    snd_nxt: u32,
    rcv_nxt: u32,
    peer_ts: Option<u32>,
    clock: u32,
}

impl Script {
    fn new(cfg: Config, peer_isn: u32, mut options: Options) -> Self {
        let base = Instant::now();
        let peer: SocketAddr = if cfg.local_v6.is_some() {
            "[2001:db8:2::2]:443".parse().unwrap()
        } else {
            "198.51.100.2:443".parse().unwrap()
        };
        let mut stack = Stack::new(cfg, base);
        let id = stack.tcp_connect(base, peer).unwrap();
        assert!(stack.take_tx_wakeup());
        assert!(!stack.take_tx_wakeup());
        let syn = pull(&mut stack, base).expect("initial SYN");
        assert_eq!(syn.dst, peer);
        assert_eq!(syn.flags, SYN);
        assert_eq!(syn.ack, 0);
        assert!(syn.payload.is_empty());
        assert!((32768..=65535).contains(&syn.src.port()));
        let clock = syn.timestamp().unwrap().0;
        if let Some((_, echo)) = options.timestamps.as_mut() {
            *echo = clock;
        }
        let snd_nxt = syn.seq.wrapping_add(1);
        let rcv_nxt = peer_isn.wrapping_add(1);
        let mut bytes = [0u8; 2000];
        let n = tcp::emit_packet(
            &mut bytes,
            peer.ip(),
            syn.src.ip(),
            &Header {
                src_port: peer.port(),
                dst_port: syn.src.port(),
                seq: peer_isn,
                ack: snd_nxt,
                flags: SYN | ACK,
                window: 32768,
                urgent: 0,
                options,
            },
            [&[], &[]],
        )
        .unwrap();
        let now = base + Duration::from_millis(10);
        assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
        assert_eq!(stack.tcp_state(id), Some(TcpState::Established));
        let handshake = pull(&mut stack, now).expect("third handshake ACK");
        let local = syn.src;
        let s = Self {
            stack,
            id,
            base,
            local,
            peer,
            syn,
            handshake,
            snd_nxt,
            rcv_nxt,
            peer_ts: options.timestamps.map(|t| t.0),
            clock,
        };
        s.handshake.assert_tcp(snd_nxt, rcv_nxt, ACK, &[]);
        s.assert_options(&s.handshake, now, s.peer_ts, &[]);
        let mut s = s;
        let (flow, ready) = s.stack.poll_event().expect("connected event");
        assert_eq!(flow, id);
        assert!(ready.contains(Ready::CONNECTED | Ready::WRITABLE));
        assert!(!ready.contains(Ready::ERROR | Ready::READ_CLOSED));
        assert!(s.stack.poll_event().is_none());
        s.quiet(now);
        s
    }

    fn at(&self, ms: u64) -> Instant {
        self.base + Duration::from_millis(ms)
    }

    fn timestamp(&self, now: Instant) -> u32 {
        self.clock
            .wrapping_add(now.duration_since(self.base).as_millis() as u32)
    }

    fn inject(&mut self, now: Instant, seq: u32, flags: u8, options: Options, data: &[u8]) {
        let mut bytes = vec![0u8; data.len() + 100];
        let n = tcp::emit_packet(
            &mut bytes,
            self.peer.ip(),
            self.local.ip(),
            &Header {
                src_port: self.peer.port(),
                dst_port: self.local.port(),
                seq,
                ack: self.snd_nxt,
                flags,
                window: 32768,
                urgent: 0,
                options,
            },
            [data, &[]],
        )
        .unwrap();
        assert_eq!(self.stack.receive(now, &bytes[..n]), Rx::Consumed);
    }

    fn input_ts(&mut self, now: Instant, seq: u32, flags: u8, ts: Option<u32>, data: &[u8]) {
        self.inject(
            now,
            seq,
            flags,
            Options {
                timestamps: ts.map(|ts| (ts, self.timestamp(now))),
                ..Options::default()
            },
            data,
        );
    }

    fn input(&mut self, now: Instant, seq: u32, flags: u8, data: &[u8]) -> Option<u32> {
        self.peer_ts = self.peer_ts.map(|ts| ts.wrapping_add(1));
        self.input_ts(now, seq, flags, self.peer_ts, data);
        self.peer_ts
    }

    fn take(&mut self, now: Instant) -> Packet {
        let p = pull(&mut self.stack, now).expect("pending wire packet");
        assert_eq!((p.src, p.dst), (self.local, self.peer));
        p
    }

    fn assert_options(&self, p: &Packet, now: Instant, echo: Option<u32>, sacks: &[(u32, u32)]) {
        assert_eq!(
            p.options,
            established_options(echo.map(|echo| (self.timestamp(now), echo)), sacks)
        );
    }

    fn ack(&mut self, now: Instant, ack: u32, echo: Option<u32>, sacks: &[(u32, u32)]) -> Packet {
        let p = self.take(now);
        p.assert_tcp(self.snd_nxt, ack, ACK, &[]);
        self.assert_options(&p, now, echo, sacks);
        p
    }

    fn quiet(&mut self, now: Instant) {
        assert!(
            pull(&mut self.stack, now).is_none(),
            "unexpected extra packet"
        );
    }

    fn readable(&mut self, required: Ready) {
        let (id, ready) = self.stack.poll_event().expect("stream readiness");
        assert_eq!(id, self.id);
        assert!(
            ready.contains(required),
            "required {required:?}, got {ready:?}"
        );
        assert!(self.stack.poll_event().is_none());
    }
}

#[test]
fn exact_syn_options_mss_and_window_scale_ipv4_ipv6() {
    for v6 in [false, true] {
        let mut s = Script::new(config(v6), 0x1234_5000, peer_options(true, true));
        let mss: u16 = if v6 { 1360 } else { 1380 };
        let mut options = vec![2, 4];
        options.extend_from_slice(&mss.to_be_bytes());
        options.extend_from_slice(&[4, 2, 8, 10]);
        options.extend_from_slice(&s.clock.to_be_bytes());
        options.extend_from_slice(&[0, 0, 0, 0, 1, 3, 3, 6]);
        assert_eq!(s.syn.options, options);
        assert_eq!(s.syn.window, 65535, "SYN window is never scaled");
        assert_eq!(s.stack.tcp_stats(s.id).unwrap().send_window, 32768);
        let now = s.at(11);
        s.input(now, s.rcv_nxt, ACK, &[]);
        assert_eq!(s.stack.tcp_stats(s.id).unwrap().send_window, 32768 << 3);
        s.quiet(now);
        assert!(u32::from(s.handshake.window) << 6 <= 3 * 1024 * 1024);
        assert!(s.handshake.window != 0);
    }
}

#[test]
fn peer_mss_and_timestamp_overhead_bound_each_data_packet() {
    for v6 in [false, true] {
        for (mss, timestamps) in [(Some(1000), true), (Some(9000), true), (None, false)] {
            let mut options = peer_options(timestamps, true);
            options.mss = mss;
            options.wscale = None;
            let mut s = Script::new(config(v6), 4000, options);
            assert_eq!(s.handshake.window, 65535, "no negotiated window scale");
            let cap = match mss {
                Some(1000) => 988,
                Some(9000) if v6 => 1348,
                Some(9000) => 1368,
                None if v6 => 1220,
                None => 536,
                _ => unreachable!(),
            };
            let data: Vec<_> = (0..2000).map(|n| n as u8).collect();
            assert_eq!(s.stack.tcp_write(s.id, &data), Ok(data.len()));
            let now = s.at(12);
            let mut off = 0;
            while off < data.len() {
                let p = s.take(now);
                let len = cap.min(data.len() - off);
                p.assert_tcp(
                    s.snd_nxt,
                    s.rcv_nxt,
                    ACK | if off + len == data.len() { tcp::PSH } else { 0 },
                    &data[off..off + len],
                );
                s.assert_options(&p, now, s.peer_ts, &[]);
                s.snd_nxt = s.snd_nxt.wrapping_add(len as u32);
                off += len;
            }
            s.quiet(now);
        }
    }
}

#[test]
fn data_is_acked_and_read_exactly_once() {
    let mut s = Script::new(config(false), 9000, peer_options(true, true));
    assert_eq!(
        s.stack.tcp_read(s.id, &mut [0; 8]),
        Err(StreamError::WouldBlock)
    );
    let data = b"packet buffers may be recycled immediately";
    let now = s.at(20);
    let ts = s.input(now, s.rcv_nxt, ACK | tcp::PSH, data);
    s.rcv_nxt += data.len() as u32;
    s.ack(now, s.rcv_nxt, ts, &[]);
    s.quiet(now);
    s.readable(Ready::READABLE);
    let mut out = [0u8; 100];
    assert_eq!(s.stack.tcp_read(s.id, &mut out[..7]), Ok(7));
    assert_eq!(&out[..7], &data[..7]);
    let n = s.stack.tcp_read(s.id, &mut out).unwrap();
    assert_eq!(&out[..n], &data[7..]);
    assert_eq!(
        s.stack.tcp_read(s.id, &mut out),
        Err(StreamError::WouldBlock)
    );
    assert!(
        !s.stack.take_tx_wakeup(),
        "tiny read must not advertise a new window"
    );
    s.quiet(now);
}

fn sack_rotation(timestamps: bool) {
    for peer_isn in [10000, u32::MAX - 250] {
        let mut s = Script::new(config(false), peer_isn, peer_options(timestamps, true));
        let slots = if timestamps { 3 } else { 4 };
        let ranges: Vec<_> = (1..=1 + 2 * (slots - 1))
            .map(|i| {
                let left = s.rcv_nxt.wrapping_add(i as u32 * 100);
                (left, left.wrapping_add(20))
            })
            .collect();
        let now = s.at(20);
        for &(left, _) in &ranges {
            s.input(now, left, ACK, &[0x43; 20]);
        }
        let mut rest: Vec<_> = ranges[..ranges.len() - 1].iter().rev().copied().collect();
        let echo = timestamps.then_some(1000);
        for round in 0..4 {
            if round != 0 {
                s.input(now, s.rcv_nxt.wrapping_sub(1), ACK, &[]);
            }
            let mut expected = vec![*ranges.last().unwrap()];
            expected.extend_from_slice(&rest[..slots - 1]);
            let p = s.ack(now, s.rcv_nxt, echo, &expected);
            assert_eq!(p.sacks(), expected);
            assert_eq!(p.options.len(), if timestamps { 40 } else { 36 });
            rest.rotate_left(slots - 1);
        }
        s.quiet(now);
        assert_eq!(
            s.stack.tcp_read(s.id, &mut [0; 1]),
            Err(StreamError::WouldBlock)
        );
    }
}

#[test]
fn sack_three_blocks_with_timestamps_are_newest_first_and_rotate() {
    sack_rotation(true);
}

#[test]
fn sack_four_blocks_without_timestamps_are_newest_first_and_rotate() {
    sack_rotation(false);
}

#[test]
fn dsack_below_ack_reports_only_duplicate_bytes() {
    let mut s = Script::new(config(false), 5000, peer_options(true, true));
    let start = s.rcv_nxt;
    let now = s.at(20);
    let ts = s.input(now, start, ACK, &[0x21; 100]);
    s.rcv_nxt += 100;
    s.ack(now, s.rcv_nxt, ts, &[]);
    let now = s.at(21);
    s.input(now, start + 20, ACK, &[0x21; 40]);
    s.ack(now, s.rcv_nxt, ts, &[(start + 20, start + 60)]);
    let now = s.at(22);
    let overlap_ts = s.input(now, start + 80, ACK, &[0x21; 40]);
    s.rcv_nxt += 20;
    s.ack(now, s.rcv_nxt, overlap_ts, &[(start + 80, start + 100)]);
    let mut data = [0; 200];
    assert_eq!(s.stack.tcp_read(s.id, &mut data), Ok(120));
    assert_eq!(&data[..120], &[0x21; 120]);
    assert_eq!(
        s.stack.tcp_read(s.id, &mut data),
        Err(StreamError::WouldBlock)
    );
}

#[test]
fn dsack_inside_ooo_precedes_the_containing_sack_block() {
    let mut s = Script::new(config(false), 6000, peer_options(true, true));
    let start = s.rcv_nxt;
    let now = s.at(20);
    s.input(now, start + 100, ACK, &[0x32; 100]);
    s.ack(now, start, Some(1000), &[(start + 100, start + 200)]);
    let now = s.at(21);
    s.input(now, start + 130, ACK, &[0x32; 20]);
    s.ack(
        now,
        start,
        Some(1000),
        &[(start + 130, start + 150), (start + 100, start + 200)],
    );
    let now = s.at(22);
    s.input(now, start.wrapping_sub(1), ACK, &[]);
    s.ack(now, start, Some(1000), &[(start + 100, start + 200)]);
    assert_eq!(
        s.stack.tcp_read(s.id, &mut [0; 200]),
        Err(StreamError::WouldBlock)
    );
}

#[test]
fn filling_ooo_holes_advances_ack_and_preserves_bytes() {
    let mut s = Script::new(config(false), 7000, peer_options(true, true));
    let start = s.rcv_nxt;
    let data: Vec<_> = (0..400).map(|n| (n * 17) as u8).collect();
    let now = s.at(20);
    for (left, right) in [(100, 200), (300, 400), (200, 300)] {
        s.input(now, start + left as u32, ACK, &data[left..right]);
    }
    s.ack(now, start, Some(1000), &[(start + 100, start + 400)]);
    s.quiet(now);
    assert_eq!(
        s.stack.tcp_read(s.id, &mut [0; 1]),
        Err(StreamError::WouldBlock)
    );
    let now = s.at(21);
    let ts = s.input(now, start, ACK, &data[..100]);
    s.ack(now, start + 400, ts, &[]);
    s.quiet(now);
    s.readable(Ready::READABLE);
    let mut out = [0; 400];
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(400));
    assert_eq!(out.as_slice(), data);
    assert_eq!(
        s.stack.tcp_read(s.id, &mut out),
        Err(StreamError::WouldBlock)
    );
}

#[test]
fn ooo_cap_drops_range_33_but_accepts_merges_and_hole_fills() {
    let mut s = Script::new(config(false), 8000, peer_options(true, true));
    let start = s.rcv_nxt;
    let data: Vec<_> = (0..670).map(|n| (n * 29) as u8).collect();
    let now = s.at(20);
    for i in 1..=33 {
        let left = i * 20;
        s.input(now, start + left as u32, ACK, &data[left..left + 10]);
    }
    assert_eq!(s.stack.tcp_stats(s.id).unwrap().ooo_drops, 1);
    s.input(now, start + 30, ACK, &data[30..40]);
    let p = s.take(now);
    p.assert_tcp(s.snd_nxt, start, ACK, &[]);
    s.assert_options(
        &p,
        now,
        Some(1000),
        &[
            (start + 20, start + 50),
            (start + 640, start + 650),
            (start + 620, start + 630),
        ],
    );
    let now = s.at(21);
    let ts = s.input(now, start, ACK, &data[..20]);
    s.ack(
        now,
        start + 50,
        ts,
        &[
            (start + 640, start + 650),
            (start + 600, start + 610),
            (start + 580, start + 590),
        ],
    );
    let now = s.at(22);
    let mut echo = None;
    for i in 2..32 {
        let left = i * 20 + 10;
        let ts = s.input(now, start + left as u32, ACK, &data[left..left + 10]);
        echo = echo.or(ts);
    }
    s.ack(now, start + 650, echo, &[]);
    let now = s.at(23);
    s.input(now, start + 660, ACK, &data[660..]);
    s.ack(now, start + 650, echo, &[(start + 660, start + 670)]);
    let now = s.at(24);
    let ts = s.input(now, start + 650, ACK, &data[650..660]);
    s.ack(now, start + 670, ts, &[]);
    assert_eq!(s.stack.tcp_stats(s.id).unwrap().ooo_drops, 1);
    let mut out = [0; 700];
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(670));
    assert_eq!(&out[..670], &data[..]);
    assert_eq!(
        s.stack.tcp_read(s.id, &mut out),
        Err(StreamError::WouldBlock)
    );
}

#[test]
fn non_sack_peer_gets_one_dupack_per_ooo_segment_in_a_batch() {
    let mut s = Script::new(config(false), 1000, peer_options(true, false));
    let now = s.at(20);
    for offset in [100, 200, 300] {
        s.input(now, s.rcv_nxt + offset, ACK, &[0x33; 20]);
    }
    for _ in 0..3 {
        s.ack(now, s.rcv_nxt, Some(1000), &[]);
    }
    s.quiet(now);
}

#[test]
fn reading_a_zero_window_emits_update_and_sticky_tx_wakeup() {
    let mut cfg = config(false);
    cfg.tcp_rcv_buf_max = 16 * 1024;
    let mut s = Script::new(cfg, 2000, peer_options(true, true));
    assert_eq!(s.syn.option(3), Some([0].as_slice()));
    let start = s.rcv_nxt;
    let data: Vec<_> = (0..16 * 1024).map(|n| (n * 7) as u8).collect();
    let now = s.at(20);
    let mut echo = None;
    for (i, bytes) in data.chunks(1000).enumerate() {
        let ts = s.input(now, start + (i * 1000) as u32, ACK, bytes);
        echo = echo.or(ts);
    }
    s.rcv_nxt += data.len() as u32;
    let ack = s.ack(now, s.rcv_nxt, echo, &[]);
    assert_eq!(ack.window, 0);
    assert!(!s.stack.take_tx_wakeup());
    let now = s.at(21);
    s.input(now, s.rcv_nxt.wrapping_sub(1), ACK, &data[data.len() - 1..]);
    assert_eq!(
        s.ack(
            now,
            s.rcv_nxt,
            echo,
            &[(s.rcv_nxt.wrapping_sub(1), s.rcv_nxt)]
        )
        .window,
        0
    );
    let mut out = vec![0; data.len()];
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(data.len()));
    assert_eq!(out, data);
    assert!(
        s.stack.take_tx_wakeup(),
        "zero-window reopening must wake the owner"
    );
    assert!(!s.stack.take_tx_wakeup(), "wakeup is take-once");
    let ack = s.ack(now, s.rcv_nxt, echo, &[]);
    assert_eq!(ack.window, 16 * 1024);
    s.quiet(now);
}

#[test]
fn reserved_receive_space_is_not_accepted_before_its_window_update_is_transmitted() {
    let mut cfg = config(false);
    cfg.tcp_rcv_buf_max = 16 * 1024;
    let mut s = Script::new(cfg, 2500, peer_options(false, true));
    let start = s.rcv_nxt;
    let bytes = vec![7; 16 * 1024];
    let now = s.at(20);
    for (i, part) in bytes.chunks(1000).enumerate() {
        s.input(now, start.wrapping_add((i * 1000) as u32), ACK, part);
    }
    s.rcv_nxt = start.wrapping_add(bytes.len() as u32);
    assert_eq!(s.ack(now, s.rcv_nxt, None, &[]).window, 0);
    let mut out = vec![0; bytes.len()];
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(bytes.len()));
    assert_eq!(out, bytes);
    assert!(s.stack.take_tx_wakeup());
    assert!(s.stack.poll_transmit(now, &mut [0; 16]).is_none());
    s.input(now, s.rcv_nxt, ACK, b"not advertised yet");
    assert_eq!(
        s.stack.tcp_read(s.id, &mut out),
        Err(StreamError::WouldBlock)
    );
    assert_eq!(s.ack(now, s.rcv_nxt, None, &[]).window, 16 * 1024);
    s.input(now, s.rcv_nxt, ACK, b"not advertised yet");
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(18));
    assert_eq!(&out[..18], b"not advertised yet");
}

fn exhaust_quickack(s: &mut Script) {
    for i in 0..16 {
        let now = s.at(20 + i);
        let ts = s.input(now, s.rcv_nxt, ACK, &[i as u8]);
        s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
        s.ack(now, s.rcv_nxt, ts, &[]);
        s.quiet(now);
    }
}

#[test]
fn sixteen_quickacks_then_a_40ms_delayed_ack() {
    let mut s = Script::new(config(false), 3000, peer_options(true, true));
    exhaust_quickack(&mut s);
    let now = s.at(40);
    let ts = s.input(now, s.rcv_nxt, ACK, b"a");
    s.rcv_nxt += 1;
    s.quiet(now);
    let deadline = now + Duration::from_millis(40);
    assert_eq!(s.stack.poll_timeout(), Some(deadline));
    let later = now + Duration::from_millis(10);
    s.input(later, s.rcv_nxt, ACK, b"b");
    s.rcv_nxt += 1;
    s.quiet(later);
    assert_eq!(
        s.stack.poll_timeout(),
        Some(deadline),
        "second small segment must not postpone ACK"
    );
    s.stack.handle_timeout(deadline - Duration::from_micros(1));
    s.quiet(deadline - Duration::from_micros(1));
    s.stack.handle_timeout(deadline);
    s.ack(deadline, s.rcv_nxt, ts, &[]);
    s.quiet(deadline);
}

fn two_full_segments(timestamps: bool) {
    let mut s = Script::new(config(false), 4000, peer_options(timestamps, true));
    exhaust_quickack(&mut s);
    let len = if timestamps { 1368 } else { 1380 };
    let now = s.at(40);
    let ts = s.input(now, s.rcv_nxt, ACK, &vec![0x51; len]);
    s.rcv_nxt += len as u32;
    s.quiet(now);
    let now = s.at(41);
    s.input(now, s.rcv_nxt, ACK, &vec![0x52; len]);
    s.rcv_nxt += len as u32;
    s.ack(now, s.rcv_nxt, ts, &[]);
    s.quiet(now);
}

#[test]
fn two_full_timestamped_segments_are_acked_without_waiting_for_timer() {
    two_full_segments(true);
}

#[test]
fn two_full_plain_segments_are_acked_without_waiting_for_timer() {
    two_full_segments(false);
}

#[test]
fn idle_restarts_sixteen_quickacks() {
    let mut s = Script::new(config(false), 5000, peer_options(true, true));
    exhaust_quickack(&mut s);
    for i in 0..16 {
        let now = s.at(5000 + i);
        s.stack.handle_timeout(now);
        let ts = s.input(now, s.rcv_nxt, ACK, b"i");
        s.rcv_nxt += 1;
        s.ack(now, s.rcv_nxt, ts, &[]);
        s.quiet(now);
    }
    let now = s.at(5016);
    let ts = s.input(now, s.rcv_nxt, ACK, b"d");
    s.rcv_nxt += 1;
    s.quiet(now);
    let deadline = now + Duration::from_millis(40);
    s.stack.handle_timeout(deadline);
    s.ack(deadline, s.rcv_nxt, ts, &[]);
}

#[test]
fn paws_rejects_old_or_missing_timestamps_without_delivering_data() {
    for v6 in [false, true] {
        let mut s = Script::new(config(v6), 6000, peer_options(true, true));
        let now = s.at(20);
        let ts = s.input(now, s.rcv_nxt, ACK, b"a");
        s.rcv_nxt += 1;
        s.ack(now, s.rcv_nxt, ts, &[]);
        assert_eq!(s.stack.tcp_read(s.id, &mut [0; 1]), Ok(1));
        s.readable(Ready::READABLE);
        let now = s.at(21);
        s.input_ts(now, s.rcv_nxt, ACK, Some(1000), b"old");
        s.ack(now, s.rcv_nxt, ts, &[]);
        assert_eq!(
            s.stack.tcp_read(s.id, &mut [0; 20]),
            Err(StreamError::WouldBlock)
        );
        assert!(s.stack.poll_event().is_none());
        let now = s.at(22);
        s.input_ts(now, s.rcv_nxt, ACK, None, b"missing");
        s.quiet(now);
        assert_eq!(
            s.stack.tcp_read(s.id, &mut [0; 20]),
            Err(StreamError::WouldBlock)
        );
        let now = s.at(23);
        let ts = s.input(now, s.rcv_nxt, ACK, b"current");
        s.rcv_nxt += 7;
        s.ack(now, s.rcv_nxt, ts, &[]);
        let mut out = [0; 20];
        assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(7));
        assert_eq!(&out[..7], b"current");
    }
}

#[test]
fn exact_rst_drains_buffered_bytes_before_sticky_reset() {
    let mut s = Script::new(config(false), 7000, peer_options(true, true));
    let now = s.at(20);
    let ts = s.input(now, s.rcv_nxt, ACK, b"retained");
    s.rcv_nxt += 8;
    s.ack(now, s.rcv_nxt, ts, &[]);
    s.readable(Ready::READABLE);
    let now = s.at(21);
    s.input(now, s.rcv_nxt, RST, &[]);
    s.quiet(now);
    assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::Closed));
    s.readable(Ready::ERROR | Ready::READABLE | Ready::READ_CLOSED);
    let mut out = [0; 4];
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(4));
    assert_eq!(&out, b"reta");
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(4));
    assert_eq!(&out, b"ined");
    for _ in 0..2 {
        assert_eq!(s.stack.tcp_read(s.id, &mut out), Err(StreamError::Reset));
        assert_eq!(s.stack.tcp_write(s.id, b"write"), Err(StreamError::Reset));
    }
    assert_eq!(s.stack.tcp_shutdown(s.id), Err(StreamError::Reset));
    assert_eq!(s.stack.stats().flows, 1);
    s.stack.tcp_close(s.id);
    assert_eq!(s.stack.stats().flows, 0);
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Err(StreamError::Stale));
    s.quiet(now);
}

#[test]
fn nonexact_in_window_rst_and_syn_challenge_without_reset_and_are_limited() {
    for flags in [RST, SYN | ACK] {
        let mut s = Script::new(config(false), 8000, peer_options(true, true));
        let now = s.at(20);
        for _ in 0..4 {
            s.input(now, s.rcv_nxt + 10, flags, &[]);
        }
        s.ack(now, s.rcv_nxt, Some(1000), &[]);
        s.quiet(now);
        assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::Established));
        assert_eq!(s.stack.tcp_stats(s.id).unwrap().challenge_acks, 1);
        let now = s.at(119);
        s.input(now, s.rcv_nxt + 10, flags, &[]);
        s.quiet(now);
        let now = s.at(120);
        s.input(now, s.rcv_nxt + 10, flags, &[]);
        s.ack(now, s.rcv_nxt, Some(1000), &[]);
        s.quiet(now);
        assert_eq!(s.stack.tcp_stats(s.id).unwrap().challenge_acks, 2);
        assert_eq!(
            s.stack.tcp_read(s.id, &mut [0; 1]),
            Err(StreamError::WouldBlock)
        );
        assert!(s.stack.poll_event().is_none());
    }
}

#[test]
fn out_of_window_syn_uses_the_same_challenge_limiter() {
    let mut s = Script::new(config(false), 9000, peer_options(true, true));
    let now = s.at(20);
    s.input(now, s.rcv_nxt + 10, SYN | ACK, &[]);
    s.ack(now, s.rcv_nxt, Some(1000), &[]);
    let now = s.at(21);
    s.input(now, s.rcv_nxt + 1_000_000, SYN | ACK, &[]);
    s.quiet(now);
    assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::Established));
}

fn peer_fin_after_our_fin(s: &mut Script, data: &[u8]) -> (Instant, Option<u32>) {
    assert_eq!(s.stack.tcp_shutdown(s.id), Ok(()));
    assert!(s.stack.take_tx_wakeup());
    let now = s.at(20);
    let fin = s.take(now);
    fin.assert_tcp(s.snd_nxt, s.rcv_nxt, FIN | ACK, &[]);
    s.assert_options(&fin, now, s.peer_ts, &[]);
    s.snd_nxt = s.snd_nxt.wrapping_add(1);
    let now = s.at(21);
    s.input(now, s.rcv_nxt, ACK, &[]);
    assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::FinWait2));
    s.quiet(now);
    let now = s.at(22);
    let ts = s.input(now, s.rcv_nxt, FIN | ACK, data);
    s.rcv_nxt = s.rcv_nxt.wrapping_add(data.len() as u32 + 1);
    assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::TimeWait));
    s.ack(now, s.rcv_nxt, ts, &[]);
    s.quiet(now);
    (now, ts)
}

#[test]
fn fin_with_data_retains_time_wait_until_application_reads_and_closes() {
    let mut s = Script::new(config(false), 10000, peer_options(true, true));
    let data = b"response delivered together with FIN";
    let (now, _) = peer_fin_after_our_fin(&mut s, data);
    s.readable(Ready::READABLE | Ready::READ_CLOSED);
    assert_eq!(s.stack.stats().flows, 1);
    assert_eq!(s.stack.stats().timewait_entries, 0);
    assert!(s.stack.stats().memory_allocated >= 16 * 1024);
    let mut out = [0; 100];
    assert_eq!(s.stack.tcp_read(s.id, &mut out[..5]), Ok(5));
    assert_eq!(&out[..5], &data[..5]);
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(data.len() - 5));
    assert_eq!(&out[..data.len() - 5], &data[5..]);
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(0));
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(0));
    assert_eq!(
        s.stack.stats().flows,
        1,
        "open handle keeps full TIME_WAIT state"
    );
    assert_eq!(s.stack.stats().timewait_entries, 0);
    s.stack.tcp_close(s.id);
    assert_eq!(s.stack.tcp_read(s.id, &mut out), Err(StreamError::Stale));
    assert_eq!(s.stack.stats().flows, 0);
    assert_eq!(s.stack.stats().timewait_entries, 1);
    assert_eq!(
        s.stack.stats().memory_committed,
        0,
        "compact TIME_WAIT holds no chunk reservations"
    );
    s.quiet(now);
}

#[test]
fn compact_time_wait_acks_retransmitted_fin_and_restarts_sixty_second_expiry() {
    for timestamps in [false, true] {
        compact_time_wait(timestamps);
    }
}

fn compact_time_wait(timestamps: bool) {
    let mut s = Script::new(config(false), 11000, peer_options(timestamps, true));
    let (closed, _) = peer_fin_after_our_fin(&mut s, &[]);
    s.stack.tcp_close(s.id);
    assert_eq!(s.stack.stats().flows, 0);
    assert_eq!(s.stack.stats().timewait_entries, 1);
    let retransmit = closed + Duration::from_secs(30);
    for _ in 0..2 {
        s.input(retransmit, s.rcv_nxt.wrapping_sub(1), FIN | ACK, &[]);
    }
    assert!(s.stack.poll_event().is_none());
    assert!(s.stack.poll_transmit(retransmit, &mut [0; 39]).is_none());
    s.ack(retransmit, s.rcv_nxt, s.peer_ts, &[]);
    s.quiet(retransmit);
    s.stack.handle_timeout(closed + Duration::from_secs(60));
    assert_eq!(
        s.stack.stats().timewait_entries,
        1,
        "FIN restarts TIME_WAIT"
    );
    s.stack
        .handle_timeout(retransmit + Duration::from_secs(60) - Duration::from_micros(1));
    assert_eq!(s.stack.stats().timewait_entries, 1);
    s.stack.handle_timeout(retransmit + Duration::from_secs(60));
    assert_eq!(s.stack.stats().timewait_entries, 0);
    assert_eq!(s.stack.stats().memory_allocated, 0);
}

#[test]
fn simultaneous_open_reuses_isn_and_negotiates_synack_options() {
    simultaneous_open(false);
}

#[test]
fn simultaneous_open_accepts_crossed_synack_and_sends_final_ack() {
    simultaneous_open(true);
}

fn simultaneous_open(final_syn: bool) {
    let base = Instant::now();
    let peer: SocketAddr = "198.51.100.2:443".parse().unwrap();
    let mut stack = Stack::new(config(false), base);
    let id = stack.tcp_connect(base, peer).unwrap();
    let syn = pull(&mut stack, base).unwrap();
    let clock = syn.timestamp().unwrap().0;
    let mut options = peer_options(true, true);
    options.timestamps = Some((1000, 0));
    let peer_isn: u32 = 12000;
    let mut bytes = [0; 2000];
    let h = Header {
        src_port: peer.port(),
        dst_port: syn.src.port(),
        seq: peer_isn,
        ack: 0,
        flags: SYN,
        window: 32768,
        urgent: 0,
        options,
    };
    let n = tcp::emit_packet(&mut bytes, peer.ip(), syn.src.ip(), &h, [&[], &[]]).unwrap();
    let now = base + Duration::from_millis(10);
    assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
    assert_eq!(stack.tcp_state(id), Some(TcpState::SynReceived));
    assert!(stack.poll_event().is_none());
    assert!(stack.poll_transmit(now, &mut [0; 59]).is_none());
    let synack = pull(&mut stack, now).expect("simultaneous-open SYNACK survives small out");
    synack.assert_tcp(syn.seq, peer_isn + 1, SYN | ACK, &[]);
    assert_eq!((synack.src, synack.dst), (syn.src, syn.dst));
    let mut expected = vec![2, 4, 0x05, 0x64, 4, 2, 8, 10];
    expected.extend_from_slice(&clock.wrapping_add(10).to_be_bytes());
    expected.extend_from_slice(&1000u32.to_be_bytes());
    expected.extend_from_slice(&[1, 3, 3, 6]);
    assert_eq!(synack.options, expected);
    let now = base + Duration::from_millis(11);
    let n = tcp::emit_packet(&mut bytes, peer.ip(), syn.src.ip(), &h, [&[], &[]]).unwrap();
    assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
    let retransmit = pull(&mut stack, now).expect("duplicate SYN repeats SYNACK");
    retransmit.assert_tcp(syn.seq, peer_isn + 1, SYN | ACK, &[]);
    let mut final_ack = h;
    final_ack.seq = peer_isn + u32::from(!final_syn);
    final_ack.ack = syn.seq.wrapping_add(1);
    final_ack.flags = ACK | if final_syn { SYN } else { 0 };
    final_ack.options = if final_syn {
        options
    } else {
        Options::default()
    };
    final_ack.options.timestamps = Some((1001, clock.wrapping_add(11)));
    let n = tcp::emit_packet(&mut bytes, peer.ip(), syn.src.ip(), &final_ack, [&[], &[]]).unwrap();
    let now = base + Duration::from_millis(12);
    assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
    assert_eq!(stack.tcp_state(id), Some(TcpState::Established));
    let (flow, ready) = stack.poll_event().expect("simultaneous open completed");
    assert_eq!(flow, id);
    assert!(ready.contains(Ready::CONNECTED | Ready::WRITABLE));
    if final_syn {
        let ack = pull(&mut stack, now).expect("crossed SYNACK needs final ACK");
        ack.assert_tcp(syn.seq.wrapping_add(1), peer_isn + 1, ACK, &[]);
        assert_eq!(
            ack.options,
            established_options(Some((clock.wrapping_add(12), 1001)), &[])
        );
    }
    assert!(pull(&mut stack, now).is_none());
}

#[test]
fn small_output_preserves_syn_ack_and_fin_obligations() {
    let base = Instant::now();
    let peer = "198.51.100.2:443".parse().unwrap();
    let mut stack = Stack::new(config(false), base);
    let id = stack.tcp_connect(base, peer).unwrap();
    assert!(stack.poll_transmit(base, &mut [0; 59]).is_none());
    assert_eq!(stack.tcp_state(id), Some(TcpState::SynSent));
    let mut exact = [0; 60];
    assert_eq!(stack.poll_transmit(base, &mut exact), Some(60));
    let syn = Packet::decode(&exact);
    assert_eq!(syn.flags, SYN);
    assert!(pull(&mut stack, base).is_none());

    let mut s = Script::new(config(false), 13000, peer_options(true, true));
    let now = s.at(20);
    let ts = s.input(now, s.rcv_nxt, ACK, b"a");
    s.rcv_nxt += 1;
    for _ in 0..2 {
        assert!(s.stack.poll_transmit(now, &mut [0; 51]).is_none());
    }
    s.ack(now, s.rcv_nxt, ts, &[]);
    s.quiet(now);
    assert_eq!(s.stack.tcp_shutdown(s.id), Ok(()));
    assert!(s.stack.take_tx_wakeup());
    for _ in 0..2 {
        assert!(s.stack.poll_transmit(now, &mut [0; 51]).is_none());
    }
    let fin = s.take(now);
    fin.assert_tcp(s.snd_nxt, s.rcv_nxt, FIN | ACK, &[]);
    s.assert_options(&fin, now, ts, &[]);
    s.snd_nxt = s.snd_nxt.wrapping_add(1);
    s.quiet(now);
    let now = s.at(21);
    s.input(now, s.rcv_nxt, ACK, &[]);
    assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::FinWait2));
    s.quiet(now);
}

fn time_wait_script(compact: bool, timestamps: bool, data: &[u8]) -> (Script, Instant) {
    let mut s = Script::new(config(false), u32::MAX - 2, peer_options(timestamps, true));
    let (closed, _) = peer_fin_after_our_fin(&mut s, data);
    s.readable(Ready::READABLE | Ready::READ_CLOSED);
    if compact {
        if !data.is_empty() {
            let mut out = vec![0; data.len()];
            assert_eq!(s.stack.tcp_read(s.id, &mut out), Ok(data.len()));
            assert_eq!(out, data);
        }
        s.stack.tcp_close(s.id);
        assert_eq!(s.stack.stats().flows, 0);
        assert_eq!(s.stack.stats().timewait_entries, 1);
        assert_eq!(s.stack.stats().memory_committed, 0);
    } else {
        assert_eq!(s.stack.stats().flows, 1);
        assert_eq!(s.stack.stats().timewait_entries, 0);
    }
    s.quiet(closed);
    (s, closed)
}

fn assert_time_wait_expiry(s: &mut Script, compact: bool, expiry: Instant) {
    s.stack.handle_timeout(expiry - Duration::from_micros(1));
    if compact {
        assert_eq!(s.stack.stats().timewait_entries, 1);
    } else {
        assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::TimeWait));
    }
    s.stack.handle_timeout(expiry);
    if compact {
        assert_eq!(s.stack.stats().timewait_entries, 0);
        assert_eq!(s.stack.stats().flows, 0);
        assert_eq!(s.stack.stats().memory_committed, 0);
    } else {
        assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::Closed));
        assert_eq!(s.stack.stats().flows, 1);
        assert_eq!(s.stack.stats().timewait_entries, 0);
    }
    s.quiet(expiry);
}

fn time_wait_ack_only_is_silent(compact: bool) {
    for timestamps in [false, true] {
        let (mut s, closed) = time_wait_script(compact, timestamps, &[]);
        let now = closed + Duration::from_secs(30);
        for _ in 0..3 {
            s.input(now, s.rcv_nxt, ACK, &[]);
            s.quiet(now);
            assert!(s.stack.poll_event().is_none());
        }
        assert_time_wait_expiry(&mut s, compact, closed + Duration::from_secs(60));
    }
}

#[test]
fn retained_time_wait_does_not_ack_valid_ack_only_packets() {
    time_wait_ack_only_is_silent(false);
}

#[test]
fn compact_time_wait_does_not_ack_valid_ack_only_packets() {
    time_wait_ack_only_is_silent(true);
}

fn invalid_fin_keeps_time_wait_deadline(
    compact: bool,
    timestamps: bool,
    mutate: impl Fn(&mut Header),
) {
    let (mut s, closed) = time_wait_script(compact, timestamps, &[]);
    let now = closed + Duration::from_secs(30);
    let mut h = Header {
        src_port: s.peer.port(),
        dst_port: s.local.port(),
        seq: s.rcv_nxt.wrapping_sub(1),
        ack: s.snd_nxt,
        flags: FIN | ACK,
        window: 32768,
        urgent: 0,
        options: Options {
            timestamps: s.peer_ts.map(|ts| (ts.wrapping_add(1), s.timestamp(now))),
            ..Options::default()
        },
    };
    mutate(&mut h);
    let mut bytes = [0; 2000];
    let n = tcp::emit_packet(&mut bytes, s.peer.ip(), s.local.ip(), &h, [&[], &[]]).unwrap();
    assert_eq!(s.stack.receive(now, &bytes[..n]), Rx::Consumed);
    if let Some(reply) = pull(&mut s.stack, now) {
        assert_eq!((reply.src, reply.dst), (s.local, s.peer));
        reply.assert_tcp(s.snd_nxt, s.rcv_nxt, ACK, &[]);
    }
    s.quiet(now);
    assert!(s.stack.poll_event().is_none());
    assert_time_wait_expiry(&mut s, compact, closed + Duration::from_secs(60));
}

#[test]
fn retained_time_wait_wrong_fin_sequence_does_not_restart_expiry() {
    for timestamps in [false, true] {
        invalid_fin_keeps_time_wait_deadline(false, timestamps, |h| {
            h.seq = h.seq.wrapping_add(1);
        });
    }
}

#[test]
fn compact_time_wait_wrong_fin_sequence_does_not_restart_expiry() {
    for timestamps in [false, true] {
        invalid_fin_keeps_time_wait_deadline(true, timestamps, |h| {
            h.seq = h.seq.wrapping_add(1);
        });
    }
}

#[test]
fn retained_time_wait_fin_ack_above_snd_nxt_does_not_restart_expiry() {
    for timestamps in [false, true] {
        invalid_fin_keeps_time_wait_deadline(false, timestamps, |h| {
            h.ack = h.ack.wrapping_add(1);
        });
    }
}

#[test]
fn compact_time_wait_fin_ack_above_snd_nxt_does_not_restart_expiry() {
    for timestamps in [false, true] {
        invalid_fin_keeps_time_wait_deadline(true, timestamps, |h| {
            h.ack = h.ack.wrapping_add(1);
        });
    }
}

#[test]
fn retained_time_wait_fin_without_negotiated_timestamp_does_not_restart_expiry() {
    invalid_fin_keeps_time_wait_deadline(false, true, |h| {
        h.options.timestamps = None;
    });
}

#[test]
fn compact_time_wait_fin_without_negotiated_timestamp_does_not_restart_expiry() {
    invalid_fin_keeps_time_wait_deadline(true, true, |h| {
        h.options.timestamps = None;
    });
}

#[test]
fn retained_time_wait_fin_with_stale_timestamp_does_not_restart_expiry() {
    invalid_fin_keeps_time_wait_deadline(false, true, |h| {
        let ts = h.options.timestamps.as_mut().unwrap();
        ts.0 = ts.0.wrapping_sub(2);
    });
}

#[test]
fn compact_time_wait_fin_with_stale_timestamp_does_not_restart_expiry() {
    invalid_fin_keeps_time_wait_deadline(true, true, |h| {
        let ts = h.options.timestamps.as_mut().unwrap();
        ts.0 = ts.0.wrapping_sub(2);
    });
}

#[test]
fn retransmitted_data_and_fin_at_the_original_fin_position_restart_time_wait() {
    let data = b"tail";
    for compact in [false, true] {
        for timestamps in [false, true] {
            let (mut s, closed) = time_wait_script(compact, timestamps, data);
            let now = closed + Duration::from_secs(30);
            let echo = s.input(
                now,
                s.rcv_nxt.wrapping_sub(data.len() as u32 + 1),
                FIN | ACK,
                data,
            );
            s.ack(now, s.rcv_nxt, echo, &[]);
            s.quiet(now);
            assert!(s.stack.poll_event().is_none());
            s.stack.handle_timeout(closed + Duration::from_secs(60));
            if compact {
                assert_eq!(s.stack.stats().timewait_entries, 1);
            } else {
                assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::TimeWait));
            }
            assert_time_wait_expiry(&mut s, compact, now + Duration::from_secs(60));
        }
    }
}

fn close_after_fin_wait2(timestamps: bool) -> (Script, Instant) {
    let mut s = Script::new(config(false), 14000, peer_options(timestamps, true));
    assert_eq!(s.stack.tcp_shutdown(s.id), Ok(()));
    let now = s.at(20);
    let fin = s.take(now);
    fin.assert_tcp(s.snd_nxt, s.rcv_nxt, FIN | ACK, &[]);
    s.snd_nxt = s.snd_nxt.wrapping_add(1);
    let now = s.at(21);
    s.input(now, s.rcv_nxt, ACK, &[]);
    assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::FinWait2));
    s.quiet(now);
    let closed = s.at(30_000);
    s.stack.handle_timeout(closed);
    assert_eq!(s.stack.tcp_state(s.id), Some(TcpState::FinWait2));
    assert_eq!(
        s.stack.tcp_read(s.id, &mut [0; 1]),
        Err(StreamError::WouldBlock)
    );
    s.quiet(closed);
    s.stack.tcp_close(s.id);
    assert_eq!(s.stack.stats().flows, 1);
    assert_eq!(s.stack.stats().timewait_entries, 0);
    s.quiet(closed);
    (s, closed)
}

#[test]
fn closing_fin_wait2_arms_sixty_second_orphan_expiry_and_releases_commitment() {
    for timestamps in [false, true] {
        let (mut s, closed) = close_after_fin_wait2(timestamps);
        assert_eq!(s.stack.tcp_read(s.id, &mut [0; 1]), Err(StreamError::Stale));
        assert_eq!(s.stack.tcp_write(s.id, b"closed"), Err(StreamError::Stale));
        assert_eq!(s.stack.tcp_shutdown(s.id), Err(StreamError::Stale));
        assert!(s.stack.poll_event().is_none());
        let expiry = closed + Duration::from_secs(60);
        let committed = s.stack.stats().memory_committed;
        assert!(committed > 0);
        assert!(s.stack.poll_timeout().is_some_and(|next| next <= expiry));
        s.stack.handle_timeout(expiry - Duration::from_micros(1));
        assert_eq!(s.stack.stats().flows, 1);
        assert_eq!(s.stack.stats().memory_committed, committed);
        s.stack.handle_timeout(expiry);
        assert_eq!(s.stack.stats().flows, 0);
        assert_eq!(s.stack.stats().timewait_entries, 0);
        assert_eq!(s.stack.stats().memory_committed, 0);
        assert_eq!(s.stack.stats().memory_allocated, 0);
        assert_eq!(s.stack.tcp_state(s.id), None);
        assert_eq!(s.stack.tcp_read(s.id, &mut [0; 1]), Err(StreamError::Stale));
        assert!(s.stack.poll_event().is_none());
        s.quiet(expiry);
    }
}

#[test]
fn simultaneous_open_crossed_synack_keeps_the_syn_window_unscaled_for_data() {
    for timestamps in [false, true] {
        let base = Instant::now();
        let peer: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let mut stack = Stack::new(config(false), base);
        let id = stack.tcp_connect(base, peer).unwrap();
        let syn = pull(&mut stack, base).unwrap();
        let peer_isn = 15000;
        let mut h = Header {
            src_port: peer.port(),
            dst_port: syn.src.port(),
            seq: peer_isn,
            ack: 0,
            flags: SYN,
            window: 100,
            urgent: 0,
            options: peer_options(timestamps, true),
        };
        let mut bytes = [0; 2000];
        let n = tcp::emit_packet(&mut bytes, peer.ip(), syn.src.ip(), &h, [&[], &[]]).unwrap();
        let now = base + Duration::from_millis(10);
        assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
        assert_eq!(stack.tcp_state(id), Some(TcpState::SynReceived));
        assert_eq!(stack.tcp_stats(id).unwrap().send_window, 100);
        let synack = pull(&mut stack, now).expect("simultaneous-open SYNACK");
        synack.assert_tcp(syn.seq, peer_isn + 1, SYN | ACK, &[]);
        h.flags = SYN | ACK;
        h.ack = syn.seq.wrapping_add(1);
        if timestamps {
            h.options.timestamps = Some((1001, synack.timestamp().unwrap().0));
        }
        let n = tcp::emit_packet(&mut bytes, peer.ip(), syn.src.ip(), &h, [&[], &[]]).unwrap();
        let now = base + Duration::from_millis(11);
        assert_eq!(stack.receive(now, &bytes[..n]), Rx::Consumed);
        assert_eq!(stack.tcp_state(id), Some(TcpState::Established));
        let ack = pull(&mut stack, now).expect("crossed SYNACK requires final ACK");
        ack.assert_tcp(syn.seq.wrapping_add(1), peer_isn + 1, ACK, &[]);
        assert_eq!((ack.src, ack.dst), (syn.src, peer));
        assert!(pull(&mut stack, now).is_none());
        let data = [0x6d; 1000];
        assert_eq!(stack.tcp_write(id, &data), Ok(data.len()));
        let packet = pull(&mut stack, now).expect("unscaled SYN window permits 100 bytes");
        packet.assert_tcp(syn.seq.wrapping_add(1), peer_isn + 1, ACK, &data[..100]);
        assert!(pull(&mut stack, now).is_none());
        assert_eq!(stack.tcp_stats(id).unwrap().send_window, 100);
        assert_eq!(stack.tcp_stats(id).unwrap().outstanding_bytes, 100);
    }
}

#[test]
fn two_equal_full_segments_on_a_smaller_path_are_acked_without_delay() {
    let mut s = Script::new(config(false), 15000, peer_options(true, true));
    exhaust_quickack(&mut s);
    let now = s.at(50);
    let start = s.rcv_nxt;
    let echo = s.input(now, start, ACK, &[0x61; 500]);
    s.input(now, start + 500, ACK, &[0x62; 500]);
    s.rcv_nxt += 1000;
    s.ack(now, s.rcv_nxt, echo, &[]);
    s.quiet(now);
}

#[test]
fn variable_sack_option_sizes_do_not_stretch_two_full_segment_acks() {
    let mut s = Script::new(config(false), 16000, peer_options(true, true));
    exhaust_quickack(&mut s);
    let now = s.at(50);
    let echo = s.input(now, s.rcv_nxt, ACK, &[0x63; 1368]);
    s.rcv_nxt += 1368;
    s.quiet(now);
    let now = s.at(90);
    s.stack.handle_timeout(now);
    s.ack(now, s.rcv_nxt, echo, &[]);
    let now = s.at(91);
    s.peer_ts = s.peer_ts.map(|ts| ts.wrapping_add(1));
    for count in 1..=2 {
        let mut options = Options {
            timestamps: s.peer_ts.map(|ts| (ts, s.timestamp(now))),
            ..Options::default()
        };
        for block in 0..count {
            options.sack.push(
                s.snd_nxt.wrapping_sub(200 + block * 100),
                s.snd_nxt.wrapping_sub(100 + block * 100),
            );
        }
        let payload = vec![0x64; 1368 - (4 + 8 * count as usize)];
        s.inject(now, s.rcv_nxt, ACK, options, &payload);
        s.rcv_nxt += payload.len() as u32;
    }
    s.ack(now, s.rcv_nxt, s.peer_ts, &[]);
    s.quiet(now);
}
