//! Deterministic public-API packet scripts; peers never use the stack's private state.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use honk_netstack::wire::{self, tcp};
use honk_netstack::{
    Config, ConnectError, DropReason, FlowId, Ready, Rx, Stack, StreamError, TcpState, UdpError,
};

const CHUNK: usize = 16 * 1024;
const MSS: u16 = 1000;

fn config() -> Config {
    let mut cfg = Config::new([0x37; 32]);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    cfg.local_v6 = Some("2001:db8::1".parse().unwrap());
    cfg
}

fn remote(v6: bool) -> SocketAddr {
    if v6 {
        "[2001:db8::2]:443"
    } else {
        "198.51.100.2:443"
    }
    .parse()
    .unwrap()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

// An independent, byte-at-a-time RFC 1071 oracle also checks the public encoder.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    for pair in bytes.chunks(2) {
        sum += (u64::from(pair[0]) << 8) | u64::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn verify_packet(bytes: &[u8], proto: u8) -> wire::IpPacket {
    let ip = wire::parse_ip(bytes).unwrap();
    assert_eq!(ip.proto, proto);
    assert_eq!(ip.payload.end, bytes.len());
    let mut pseudo = Vec::new();
    match (ip.src, ip.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            assert_eq!(checksum(&bytes[..ip.payload.start]), 0);
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&[0, proto]);
            pseudo.extend_from_slice(&(ip.payload.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&(ip.payload.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, proto]);
        }
        _ => panic!("mixed address families"),
    }
    pseudo.extend_from_slice(&bytes[ip.payload.clone()]);
    assert_eq!(checksum(&pseudo), 0, "invalid outgoing transport checksum");
    ip
}

struct Packet {
    bytes: Vec<u8>,
    ip: wire::IpPacket,
    h: tcp::Header,
    offset: usize,
}

impl Packet {
    fn decode(bytes: Vec<u8>) -> Self {
        let ip = verify_packet(&bytes, wire::PROTO_TCP);
        let (h, offset) = tcp::parse(&bytes[ip.payload.clone()]).unwrap();
        Self {
            bytes,
            ip,
            h,
            offset,
        }
    }

    fn data(&self) -> &[u8] {
        &self.bytes[self.ip.payload.start + self.offset..self.ip.payload.end]
    }

    fn end(&self) -> u32 {
        self.h
            .seq
            .wrapping_add(self.data().len() as u32)
            .wrapping_add(u32::from(self.h.flags & tcp::FIN != 0))
            .wrapping_add(u32::from(self.h.flags & tcp::SYN != 0))
    }
}

fn pull(stack: &mut Stack, now: Instant) -> Option<Packet> {
    let mut out = [0u8; 2048];
    stack
        .poll_transmit(now, &mut out)
        .map(|n| Packet::decode(out[..n].to_vec()))
}

fn drain(stack: &mut Stack, now: Instant) -> Vec<Packet> {
    let mut packets = Vec::new();
    while let Some(packet) = pull(stack, now) {
        assert!(packets.len() < 256, "transmit never quiesced");
        packets.push(packet);
    }
    packets
}

fn events(stack: &mut Stack, id: FlowId) -> Ready {
    let mut ready = Ready::default();
    while let Some((flow, bits)) = stack.poll_event() {
        assert_eq!(flow, id);
        ready |= bits;
    }
    ready
}

fn encode_tcp(src: SocketAddr, dst: SocketAddr, h: &tcp::Header, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 2048];
    let n = tcp::emit_packet(&mut bytes, src.ip(), dst.ip(), h, [data, &[]]).unwrap();
    bytes.truncate(n);
    bytes
}

struct Peer {
    id: FlowId,
    local: SocketAddr,
    remote: SocketAddr,
    start: u32,
    next: u32,
    epoch: Instant,
    timestamps: bool,
    echo: u32,
    window: u16,
}

impl Peer {
    fn header(&self, now: Instant, ack: u32) -> tcp::Header {
        tcp::Header {
            src_port: self.remote.port(),
            dst_port: self.local.port(),
            seq: self.next,
            ack,
            flags: tcp::ACK,
            window: self.window,
            urgent: 0,
            options: tcp::Options {
                timestamps: self.timestamps.then_some((
                    100_000u32.wrapping_add(now.duration_since(self.epoch).as_millis() as u32),
                    self.echo,
                )),
                ..tcp::Options::default()
            },
        }
    }

    fn packet(&self, h: &tcp::Header, data: &[u8]) -> Vec<u8> {
        encode_tcp(self.remote, self.local, h, data)
    }

    fn ack(&self, stack: &mut Stack, now: Instant, ack: u32) {
        assert_eq!(
            stack.receive(now, &self.packet(&self.header(now, ack), &[])),
            Rx::Consumed
        );
    }
}

fn open(
    stack: &mut Stack,
    now: &mut Instant,
    dst: SocketAddr,
    timestamps: bool,
    sack: bool,
) -> Peer {
    open_mss(stack, now, dst, timestamps, sack, MSS)
}

fn open_mss(
    stack: &mut Stack,
    now: &mut Instant,
    dst: SocketAddr,
    timestamps: bool,
    sack: bool,
    mss: u16,
) -> Peer {
    let epoch = *now;
    let id = stack.tcp_connect(*now, dst).unwrap();
    let syn = pull(stack, *now).expect("initial SYN");
    assert_eq!(syn.h.flags, tcp::SYN);
    assert_eq!(syn.ip.dst, dst.ip());
    assert_eq!(syn.h.dst_port, dst.port());
    assert_eq!(
        syn.h.options.mss,
        Some(if dst.is_ipv6() { 1360 } else { 1380 })
    );
    let peer = Peer {
        id,
        local: SocketAddr::new(syn.ip.src, syn.h.src_port),
        remote: dst,
        start: syn.end(),
        next: 0x1020_3041,
        epoch,
        timestamps,
        echo: syn.h.options.timestamps.unwrap().0,
        window: 60_000,
    };
    let mut h = peer.header(*now, peer.start);
    h.seq = peer.next.wrapping_sub(1);
    h.flags |= tcp::SYN;
    h.options.mss = Some(mss);
    h.options.sack_permitted = sack;
    *now += Duration::from_millis(10);
    assert_eq!(stack.receive(*now, &peer.packet(&h, &[])), Rx::Consumed);
    assert_eq!(stack.tcp_state(id), Some(TcpState::Established));
    let ack = pull(stack, *now).expect("handshake ACK");
    assert_eq!(
        (ack.h.flags, ack.h.seq, ack.h.ack),
        (tcp::ACK, peer.start, peer.next)
    );
    assert!(ack.data().is_empty());
    assert!(pull(stack, *now).is_none());
    assert!(events(stack, id).contains(Ready::CONNECTED | Ready::WRITABLE));
    peer
}

fn assert_stream_stale(stack: &mut Stack, id: FlowId) {
    assert_eq!(stack.tcp_write(id, b"x"), Err(StreamError::Stale));
    assert_eq!(stack.tcp_read(id, &mut [0; 1]), Err(StreamError::Stale));
    assert_eq!(stack.tcp_shutdown(id), Err(StreamError::Stale));
    assert_eq!(stack.tcp_state(id), None);
    assert!(stack.tcp_stats(id).is_none());
}

#[test]
fn data_sequence_payload_checksums_and_no_nagle() {
    for v6 in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let peer = open(&mut stack, &mut now, remote(v6), true, true);
        assert_eq!(stack.tcp_write(peer.id, b"a"), Ok(1));
        assert!(stack.take_tx_wakeup());
        assert!(!stack.take_tx_wakeup());
        let first = pull(&mut stack, now).expect("a short write must not wait for ACK");
        assert_eq!(first.data(), b"a");
        assert_eq!(stack.tcp_write(peer.id, b"bc"), Ok(2));
        let second = pull(&mut stack, now).expect("no Nagle behind outstanding data");
        assert_eq!(
            (second.h.seq, second.data()),
            (first.end(), b"bc".as_slice())
        );
        let bytes = pattern(3501);
        assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
        let packets = drain(&mut stack, now);
        let mut seq = second.end();
        let mut got = Vec::new();
        for packet in &packets {
            assert_eq!((packet.h.seq, packet.h.ack), (seq, peer.next));
            assert_eq!(packet.ip.src, peer.local.ip());
            assert_eq!(packet.ip.dst, peer.remote.ip());
            assert_eq!(packet.h.flags & (tcp::SYN | tcp::RST | tcp::FIN), 0);
            assert!(packet.h.flags & tcp::ACK != 0);
            assert!(packet.h.options.timestamps.is_some());
            assert!(packet.data().len() <= usize::from(MSS) - 12);
            assert!(packet.bytes.len() <= 1420);
            got.extend_from_slice(packet.data());
            seq = packet.end();
        }
        assert_eq!(got, bytes);
        assert!(packets.last().unwrap().h.flags & tcp::PSH != 0);
        assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 3504);
        now += Duration::from_millis(10);
        peer.ack(&mut stack, now, seq);
        assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
        assert_eq!(stack.tcp_write(peer.id, b"again"), Ok(5));
        let next = pull(&mut stack, now).unwrap();
        assert_eq!((next.h.seq, next.data()), (seq, b"again".as_slice()));
    }
}

#[test]
fn cumulative_ack_releases_buffer_and_rearms_writable_after_would_block() {
    let mut cfg = config();
    cfg.tcp_snd_buf_max = 2 * CHUNK;
    let mut now = Instant::now();
    let mut stack = Stack::new(cfg, now);
    let peer = open(&mut stack, &mut now, remote(false), false, false);
    let bytes = pattern(2 * CHUNK);
    assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
    assert_eq!(
        stack.tcp_write(peer.id, b"blocked"),
        Err(StreamError::WouldBlock)
    );
    assert!(events(&mut stack, peer.id).is_empty());
    let mut done = 0usize;
    let mut writable = false;
    for _ in 0..16 {
        let packets = drain(&mut stack, now);
        assert!(!packets.is_empty(), "queued data must progress");
        for packet in &packets {
            assert_eq!(packet.h.seq, peer.start.wrapping_add(done as u32));
            assert_eq!(packet.data(), &bytes[done..done + packet.data().len()]);
            done += packet.data().len();
        }
        now += Duration::from_millis(10);
        peer.ack(&mut stack, now, packets.last().unwrap().end());
        writable |= events(&mut stack, peer.id).contains(Ready::WRITABLE);
        if done == bytes.len() {
            break;
        }
    }
    assert_eq!(done, bytes.len());
    assert!(
        writable,
        "ACK freeing a previously full buffer must publish WRITABLE"
    );
    assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
    assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
}

#[test]
fn newreno_third_duplicate_ack_retransmits_first_loss() {
    let mut now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let peer = open(&mut stack, &mut now, remote(false), false, false);
    let bytes = pattern(10 * usize::from(MSS));
    assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
    let packets = drain(&mut stack, now);
    assert_eq!(packets.len(), 10);
    now += Duration::from_millis(10);
    for _ in 0..3 {
        peer.ack(&mut stack, now, peer.start);
    }
    let retrans =
        pull(&mut stack, now).expect("third duplicate ACK must retransmit without waiting for RTO");
    assert_eq!(
        (retrans.h.seq, retrans.data()),
        (peer.start, packets[0].data())
    );
    let stats = stack.tcp_stats(peer.id).unwrap();
    assert_eq!(stats.retrans_segments, 1);
    assert_eq!(stats.ssthresh, 5000);
}

#[test]
fn newreno_partial_ack_retransmits_next_hole_and_full_ack_exits_once() {
    let mut now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let peer = open(&mut stack, &mut now, remote(false), false, false);
    let bytes = pattern(5000);
    assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
    let initial = drain(&mut stack, now);
    assert_eq!(initial.len(), 5);
    now += Duration::from_millis(10);
    for _ in 0..3 {
        peer.ack(&mut stack, now, peer.start);
    }
    let first = pull(&mut stack, now).expect("first lost segment");
    assert_eq!(
        (first.h.seq, first.data()),
        (initial[0].h.seq, initial[0].data())
    );
    let threshold = stack.tcp_stats(peer.id).unwrap().ssthresh;
    now += Duration::from_millis(10);
    peer.ack(&mut stack, now, initial[2].end());
    let next = pull(&mut stack, now).expect("partial ACK must retransmit the next hole");
    assert_eq!(
        (next.h.seq, next.data()),
        (initial[3].h.seq, initial[3].data())
    );
    assert_eq!(stack.tcp_stats(peer.id).unwrap().ssthresh, threshold);
    peer.ack(&mut stack, now, initial[4].end());
    let stats = stack.tcp_stats(peer.id).unwrap();
    assert_eq!(
        stats.ssthresh, threshold,
        "full recovery ACK must not cut ssthresh again"
    );
    assert_eq!(
        (
            stats.outstanding_bytes,
            stats.lost_bytes,
            stats.retrans_in_flight
        ),
        (0, 0, 0)
    );
    assert!((u32::from(MSS)..=threshold).contains(&stats.cwnd));
    assert!(pull(&mut stack, now).is_none());
    assert_eq!(stack.tcp_write(peer.id, b"after recovery"), Ok(14));
    let fresh = pull(&mut stack, now).expect("new data after full ACK");
    assert_eq!(
        (fresh.h.seq, fresh.data()),
        (initial[4].end(), b"after recovery".as_slice())
    );
    for _ in 0..3 {
        peer.ack(&mut stack, now, fresh.h.seq);
    }
    assert_eq!(
        stack.tcp_stats(peer.id).unwrap().ssthresh,
        2 * u32::from(MSS),
        "a later loss episode must be able to enter recovery again"
    );
    let retrans = pull(&mut stack, now).expect("new episode after full-ACK recovery exit");
    assert_eq!((retrans.h.seq, retrans.data()), (fresh.h.seq, fresh.data()));
}

#[test]
fn sack_skips_delivered_segments_but_never_releases_send_bytes() {
    let mut cfg = config();
    cfg.tcp_snd_buf_max = 2 * CHUNK;
    let mut now = Instant::now();
    let mut stack = Stack::new(cfg, now);
    let peer = open(&mut stack, &mut now, remote(false), false, true);
    let bytes = pattern(2 * CHUNK);
    assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
    assert_eq!(stack.tcp_write(peer.id, b"x"), Err(StreamError::WouldBlock));
    let initial = drain(&mut stack, now);
    assert_eq!(initial.len(), 10);
    let allocated = stack.stats().memory_allocated;
    let mut h = peer.header(now, peer.start);
    h.options.sack.push(initial[1].h.seq, initial[9].end());
    now += Duration::from_millis(10);
    assert_eq!(stack.receive(now, &peer.packet(&h, &[])), Rx::Consumed);
    let stats = stack.tcp_stats(peer.id).unwrap();
    assert_eq!(
        (stats.outstanding_bytes, stats.sacked_bytes),
        (10_000, 9000)
    );
    assert_eq!(stack.stats().memory_allocated, allocated);
    assert_eq!(
        stack.tcp_write(peer.id, b"still full"),
        Err(StreamError::WouldBlock)
    );
    assert!(events(&mut stack, peer.id).is_empty());
    let retrans = pull(&mut stack, now).expect("SACK exposes the first hole");
    assert_eq!(
        (retrans.h.seq, retrans.data()),
        (initial[0].h.seq, initial[0].data())
    );
    for packet in drain(&mut stack, now) {
        let offset = packet.h.seq.wrapping_sub(peer.start) as usize;
        assert!(
            offset >= 10_000,
            "SACKed bytes must be skipped during recovery"
        );
        assert_eq!(packet.data(), &bytes[offset..offset + packet.data().len()]);
    }
    assert_eq!(
        stack.tcp_write(peer.id, b"SACK is not a cumulative ACK"),
        Err(StreamError::WouldBlock)
    );
}

#[test]
fn syn_rto_starts_at_one_second_and_backs_off() {
    let now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let id = stack.tcp_connect(now, remote(false)).unwrap();
    let syn = pull(&mut stack, now).unwrap();
    assert_eq!(stack.tcp_stats(id).unwrap().rto, Duration::from_secs(1));
    assert_eq!(stack.poll_timeout(), Some(now + Duration::from_secs(1)));
    stack.handle_timeout(now + Duration::from_millis(999));
    assert!(pull(&mut stack, now + Duration::from_millis(999)).is_none());
    let mut deadline = now + Duration::from_secs(1);
    for interval in [2, 4, 8] {
        stack.handle_timeout(deadline);
        let retrans = pull(&mut stack, deadline).expect("SYN retransmission");
        assert_eq!((retrans.h.flags, retrans.h.seq), (tcp::SYN, syn.h.seq));
        assert_eq!(
            stack.tcp_stats(id).unwrap().rto,
            Duration::from_secs(interval)
        );
        assert_eq!(
            stack.poll_timeout(),
            Some(deadline + Duration::from_secs(interval))
        );
        deadline += Duration::from_secs(interval);
    }
}

#[test]
fn data_rto_floor_backoff_and_karn_ignore_ambiguous_rtt() {
    let mut now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let peer = open(&mut stack, &mut now, remote(false), false, false);
    assert_eq!(
        stack.tcp_stats(peer.id).unwrap().rto,
        Duration::from_millis(200)
    );
    let srtt = stack.tcp_stats(peer.id).unwrap().srtt;
    assert_eq!(stack.tcp_write(peer.id, b"ambiguous"), Ok(9));
    let data = pull(&mut stack, now).unwrap();
    stack.handle_timeout(now + Duration::from_millis(199));
    assert!(pull(&mut stack, now + Duration::from_millis(199)).is_none());
    for (elapsed, rto) in [(200, 400), (600, 800)] {
        let due = now + Duration::from_millis(elapsed);
        stack.handle_timeout(due);
        let retrans = pull(&mut stack, due).expect("data RTO retransmission");
        assert_eq!((retrans.h.seq, retrans.data()), (data.h.seq, data.data()));
        assert_eq!(
            stack.tcp_stats(peer.id).unwrap().rto,
            Duration::from_millis(rto)
        );
    }
    now += Duration::from_millis(620);
    peer.ack(&mut stack, now, data.end());
    let stats = stack.tcp_stats(peer.id).unwrap();
    assert_eq!(stats.rto_count, 2);
    assert_eq!(
        stats.srtt, srtt,
        "Karn forbids samples without negotiated timestamps after retransmit"
    );
    assert_eq!(stats.rto, Duration::from_millis(800));
    assert_eq!(stack.tcp_write(peer.id, b"fresh"), Ok(5));
    let fresh = pull(&mut stack, now).unwrap();
    now += Duration::from_millis(20);
    peer.ack(&mut stack, now, fresh.end());
    assert_eq!(
        stack.tcp_stats(peer.id).unwrap().srtt,
        Some(Duration::from_micros(11_250))
    );
    assert_eq!(
        stack.tcp_stats(peer.id).unwrap().rto,
        Duration::from_millis(200)
    );
}

#[test]
fn persist_probe_and_window_ack_resume_queued_data() {
    let mut now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let mut peer = open(&mut stack, &mut now, remote(false), true, true);
    peer.window = 0;
    peer.ack(&mut stack, now, peer.start);
    assert_eq!(stack.tcp_write(peer.id, b"held by zero window"), Ok(19));
    assert!(pull(&mut stack, now).is_none());
    let due = now + Duration::from_millis(200);
    stack.handle_timeout(due);
    let probe = pull(&mut stack, due).expect("zero window must not deadlock");
    assert_eq!(probe.h.flags, tcp::ACK);
    assert!(probe.data().is_empty());
    assert_eq!(probe.h.seq, peer.start.wrapping_sub(1));
    assert_eq!(stack.tcp_stats(peer.id).unwrap().rto_count, 0);
    assert!(pull(&mut stack, due).is_none());
    let next = stack.poll_timeout().unwrap();
    assert!(next >= due + Duration::from_millis(400));
    peer.window = 60_000;
    peer.ack(&mut stack, due, peer.start);
    let data = pull(&mut stack, due).expect("window-update ACK enables data without another write");
    assert_eq!(
        (data.h.seq, data.data()),
        (peer.start, b"held by zero window".as_slice())
    );
}

fn ptb(peer: &Peer, original: &[u8], mtu: u32) -> Vec<u8> {
    let mut out = vec![0u8; 2048];
    let n =
        wire::icmp::emit_packet_too_big(&mut out, peer.remote.ip(), peer.local.ip(), mtu, original)
            .unwrap();
    out.truncate(n);
    out
}

#[test]
fn ptb_splits_retransmissions_without_losing_payload_bytes() {
    for v6 in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let peer = open_mss(&mut stack, &mut now, remote(v6), true, true, 1460);
        let mtu = 1280;
        let bytes = pattern(1420 - wire::ip_header_len(v6) - 32);
        assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
        let original = pull(&mut stack, now).unwrap();
        assert_eq!(
            stack.receive(now, &ptb(&peer, &original.bytes, mtu)),
            Rx::Consumed
        );
        let retrans = drain(&mut stack, now);
        assert_eq!(retrans.len(), 2);
        let mut seq = peer.start;
        let mut recovered = Vec::new();
        for packet in &retrans {
            assert_eq!(packet.h.seq, seq);
            assert!(packet.bytes.len() <= mtu as usize);
            assert!(packet.h.options.timestamps.is_some());
            recovered.extend_from_slice(packet.data());
            seq = packet.end();
        }
        assert_eq!(recovered, bytes);
        assert_eq!(
            stack.tcp_stats(peer.id).unwrap().retrans_bytes,
            bytes.len() as u64
        );
        peer.ack(&mut stack, now, seq);
        assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
    }
}

#[test]
fn ptb_bad_quote_sequence_is_ignored_and_pmtu_only_decreases() {
    for v6 in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let peer = open(&mut stack, &mut now, remote(v6), true, true);
        assert_eq!(stack.tcp_write(peer.id, &pattern(900)), Ok(900));
        let original = pull(&mut stack, now).unwrap();
        let first = if v6 { 1280 } else { 900 };
        let smaller = if v6 { 1000 } else { 700 };
        for invalid in [peer.start.wrapping_sub(1), original.end()] {
            let mut h = original.h;
            h.seq = invalid;
            let quote = encode_tcp(peer.local, peer.remote, &h, original.data());
            assert_eq!(stack.receive(now, &ptb(&peer, &quote, first)), Rx::Consumed);
            assert_eq!(stack.tcp_stats(peer.id).unwrap().pmtu, 1420);
            assert!(pull(&mut stack, now).is_none());
        }
        for (reported, expected) in [
            (first, first),
            (1400, first),
            (smaller, if v6 { 1280 } else { 700 }),
        ] {
            assert_eq!(
                stack.receive(now, &ptb(&peer, &original.bytes, reported)),
                Rx::Consumed
            );
            assert_eq!(stack.tcp_stats(peer.id).unwrap().pmtu, expected as u16);
        }
    }
}

#[test]
fn tcp_payload_budget_includes_timestamp_and_sack_options() {
    for v6 in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let peer = open_mss(&mut stack, &mut now, remote(v6), true, true, 1460);
        assert_eq!(stack.tcp_write(peer.id, b"quote"), Ok(5));
        let original = pull(&mut stack, now).unwrap();
        let mtu = if v6 { 1280 } else { 700 };
        assert_eq!(
            stack.receive(now, &ptb(&peer, &original.bytes, mtu)),
            Rx::Consumed
        );
        peer.ack(&mut stack, now, original.end());
        for gap in [100, 300, 500] {
            let mut h = peer.header(now, original.end());
            h.seq = peer.next.wrapping_add(gap);
            assert_eq!(
                stack.receive(now, &peer.packet(&h, &[0xab; 50])),
                Rx::Consumed
            );
        }
        let bytes = pattern(3500);
        assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
        let packets = drain(&mut stack, now);
        assert!(!packets.is_empty());
        let mut recovered = Vec::new();
        for packet in packets {
            assert_eq!(packet.offset, 60);
            assert_eq!(packet.h.options.sack.len(), 3);
            assert!(packet.h.options.timestamps.is_some());
            assert!(packet.data().len() <= mtu as usize - wire::ip_header_len(v6) - 60);
            assert!(packet.bytes.len() <= mtu as usize);
            recovered.extend_from_slice(packet.data());
        }
        assert_eq!(recovered, bytes);
    }
}

#[test]
fn control_flood_does_not_starve_data_with_one_packet_pull_budget() {
    let mut now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let peer = open(&mut stack, &mut now, remote(false), true, true);
    assert_eq!(stack.tcp_write(peer.id, b"business"), Ok(8));
    let mut h = peer.header(now, peer.start);
    h.dst_port = peer.local.port().wrapping_add(1);
    h.flags = tcp::SYN;
    for _ in 0..512 {
        assert_eq!(
            stack.receive(now, &peer.packet(&h, &[])),
            Rx::Dropped(DropReason::NoFlow)
        );
    }
    assert!(stack.stats().control_dropped > 0);
    let mut delivered = false;
    for _ in 0..4 {
        // Every iteration is a fresh RX batch followed by exactly one pull.
        assert_eq!(
            stack.receive(now, &peer.packet(&h, &[])),
            Rx::Dropped(DropReason::NoFlow)
        );
        let packet = pull(&mut stack, now).unwrap();
        if packet.h.src_port == peer.local.port() {
            assert_eq!(packet.data(), b"business");
            delivered = true;
            break;
        }
        assert!(packet.h.flags & tcp::RST != 0);
    }
    assert!(
        delivered,
        "persistent control traffic cannot monopolize budget=1"
    );
}

fn assert_budget(stack: &Stack, limit: usize) {
    let stats = stack.stats();
    assert!(
        stats.memory_allocated <= limit,
        "allocated {} > {limit}",
        stats.memory_allocated
    );
    assert!(
        stats.memory_committed <= limit,
        "committed {} > {limit}",
        stats.memory_committed
    );
}

#[test]
fn exhausted_shared_pool_preserves_each_admitted_flows_request_response_floor() {
    let mut cfg = config();
    cfg.max_flows = 4;
    cfg.memory_limit = cfg.max_flows as usize * 2 * CHUNK;
    let limit = cfg.memory_limit;
    let mut now = Instant::now();
    let mut stack = Stack::new(cfg, now);
    let mut peers = Vec::new();
    // Metadata is also truesize: admission may reject before max_flows, never after acceptance.
    for port in 443..447 {
        let dst = SocketAddr::new(remote(false).ip(), port);
        match stack.tcp_connect(now, dst) {
            Ok(id) => {
                let syn = pull(&mut stack, now).unwrap();
                let peer = Peer {
                    id,
                    local: SocketAddr::new(syn.ip.src, syn.h.src_port),
                    remote: dst,
                    start: syn.end(),
                    next: 1001,
                    epoch: now,
                    timestamps: false,
                    echo: 0,
                    window: 60_000,
                };
                let mut h = peer.header(now, peer.start);
                h.flags |= tcp::SYN;
                h.seq -= 1;
                h.options.mss = Some(MSS);
                assert_eq!(stack.receive(now, &peer.packet(&h, &[])), Rx::Consumed);
                assert!(pull(&mut stack, now).is_some());
                assert!(pull(&mut stack, now).is_none());
                events(&mut stack, id);
                peers.push(peer);
            }
            Err(ConnectError::Memory) => break,
            other => panic!("unexpected admission result: {other:?}"),
        }
        assert_budget(&stack, limit);
    }
    assert!(!peers.is_empty());
    let bytes = pattern(CHUNK);
    for peer in &peers {
        assert_eq!(
            stack.tcp_write(peer.id, &bytes),
            Ok(CHUNK),
            "every admitted flow owns one TX chunk"
        );
        assert_eq!(
            stack.tcp_write(peer.id, b"full"),
            Err(StreamError::WouldBlock)
        );
        assert_budget(&stack, limit);
    }
    let mut done = vec![0usize; peers.len()];
    for _ in 0..16 {
        let packets = drain(&mut stack, now);
        assert_budget(&stack, limit);
        for packet in packets {
            let index = peers
                .iter()
                .position(|p| p.local.port() == packet.h.src_port)
                .unwrap();
            let peer = &peers[index];
            assert_eq!(packet.h.seq, peer.start.wrapping_add(done[index] as u32));
            assert_eq!(
                packet.data(),
                &bytes[done[index]..done[index] + packet.data().len()]
            );
            done[index] += packet.data().len();
            peer.ack(&mut stack, now, packet.end());
        }
        assert_budget(&stack, limit);
        if done.iter().all(|&n| n == CHUNK) {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(done.iter().all(|&n| n == CHUNK));
    for peer in &peers {
        for (offset, data) in bytes.chunks(1000).enumerate() {
            let mut h = peer.header(now, peer.start.wrapping_add(CHUNK as u32));
            h.seq = peer.next.wrapping_add((offset * 1000) as u32);
            assert_eq!(stack.receive(now, &peer.packet(&h, data)), Rx::Consumed);
        }
        assert_budget(&stack, limit);
    }
    drain(&mut stack, now);
    for peer in &peers {
        let mut out = vec![0u8; CHUNK];
        assert_eq!(
            stack.tcp_read(peer.id, &mut out),
            Ok(CHUNK),
            "every floor also owns an RX chunk"
        );
        assert_eq!(out, bytes);
        assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
        assert_budget(&stack, limit);
    }
    let mut writable = Vec::new();
    while let Some((flow, ready)) = stack.poll_event() {
        if ready.contains(Ready::WRITABLE) {
            writable.push(flow);
        }
    }
    for peer in &peers {
        assert_eq!(stack.tcp_write(peer.id, b"next request"), Ok(12));
        assert!(
            writable.contains(&peer.id),
            "ACK freeing the guaranteed TX floor must wake its blocked writer even with no shared chunks"
        );
    }
}

#[test]
fn stale_handles_cannot_close_abort_or_send_through_a_reused_slot() {
    let mut now = Instant::now();
    let mut cfg = config();
    cfg.max_flows = 1;
    let mut stack = Stack::new(cfg, now);
    let closed = stack.tcp_connect(now, remote(false)).unwrap();
    stack.tcp_close(closed);
    assert_stream_stale(&mut stack, closed);
    let aborted = stack.tcp_connect(now, remote(false)).unwrap();
    assert_ne!(closed, aborted);
    stack.tcp_abort(aborted);
    assert_stream_stale(&mut stack, aborted);
    let established = open(&mut stack, &mut now, remote(false), true, true);
    stack.tcp_abort(established.id);
    assert_stream_stale(&mut stack, established.id);
    let reset = pull(&mut stack, now).expect("abort must emit a reset before freeing its slot");
    assert_eq!(reset.h.flags & (tcp::RST | tcp::FIN), tcp::RST);
    assert_eq!(reset.h.seq, established.start);
    let udp = stack.udp_bind(Some(5353)).unwrap();
    stack.udp_close(udp);
    let live = stack.udp_bind(Some(5353)).unwrap();
    assert_ne!(udp, live);
    for stale in [closed, aborted, established.id, udp] {
        stack.tcp_close(stale);
        stack.tcp_abort(stale);
        stack.udp_close(stale);
        assert_stream_stale(&mut stack, stale);
        assert_eq!(
            stack.udp_send(stale, remote(false), b"x", &mut [0; 100]),
            Err(UdpError::Stale)
        );
    }
    assert_stream_stale(&mut stack, live);
    assert!(
        stack
            .udp_send(live, remote(false), b"live", &mut [0; 100])
            .is_ok()
    );
    assert_eq!(stack.stats().flows, 1);
}

#[test]
fn shutdown_orders_queued_data_before_fin_and_closes_writes() {
    let mut now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let peer = open(&mut stack, &mut now, remote(false), true, true);
    let bytes = pattern(15_000);
    assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(bytes.len()));
    assert_eq!(stack.tcp_shutdown(peer.id), Ok(()));
    assert_eq!(stack.tcp_shutdown(peer.id), Ok(()));
    assert_eq!(stack.tcp_write(peer.id, b"late"), Err(StreamError::Closed));
    let mut done = 0;
    let mut fin = None;
    for _ in 0..16 {
        let packets = drain(&mut stack, now);
        assert!(!packets.is_empty());
        for packet in &packets {
            assert_eq!(packet.h.seq, peer.start.wrapping_add(done as u32));
            assert_eq!(packet.data(), &bytes[done..done + packet.data().len()]);
            done += packet.data().len();
            if packet.h.flags & tcp::FIN != 0 {
                assert_eq!(done, bytes.len(), "FIN cannot overtake queued data");
                fin = Some(packet.end());
            }
        }
        now += Duration::from_millis(10);
        peer.ack(&mut stack, now, packets.last().unwrap().end());
        if fin.is_some() {
            break;
        }
    }
    assert_eq!(fin, Some(peer.start.wrapping_add(bytes.len() as u32 + 1)));
    assert_eq!(stack.tcp_state(peer.id), Some(TcpState::FinWait2));
    let mut h = peer.header(now, fin.unwrap());
    h.flags |= tcp::FIN;
    assert_eq!(stack.receive(now, &peer.packet(&h, &[])), Rx::Consumed);
    let ack = pull(&mut stack, now).unwrap();
    assert_eq!(ack.h.ack, peer.next.wrapping_add(1));
    assert_eq!(stack.tcp_read(peer.id, &mut [0; 1]), Ok(0));
    assert_eq!(stack.tcp_write(peer.id, b"late"), Err(StreamError::Closed));
}

#[test]
fn close_with_unread_data_sends_reset_not_fin() {
    for drain_first in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let peer = open(&mut stack, &mut now, remote(false), true, true);
        let h = peer.header(now, peer.start);
        assert_eq!(stack.receive(now, &peer.packet(&h, b"reply")), Rx::Consumed);
        drain(&mut stack, now);
        if drain_first {
            let mut out = [0u8; 5];
            assert_eq!(stack.tcp_read(peer.id, &mut out), Ok(5));
            assert_eq!(&out, b"reply");
        }
        stack.tcp_close(peer.id);
        assert_stream_stale(&mut stack, peer.id);
        let close = pull(&mut stack, now).unwrap();
        assert_eq!(
            close.h.flags & (tcp::RST | tcp::FIN),
            if drain_first { tcp::FIN } else { tcp::RST }
        );
        assert_eq!(
            (close.h.seq, close.h.ack),
            (peer.start, peer.next.wrapping_add(5))
        );
    }
}

fn encode_udp(src: SocketAddr, dst: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 2048];
    let n = wire::udp::emit_packet(&mut out, src, dst, data).unwrap();
    out.truncate(n);
    out
}

#[test]
fn udp_v4_v6_ranges_and_multiple_destinations_share_one_source() {
    let now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let id = stack.udp_bind(None).unwrap();
    let mut port = None;
    for dst in [
        remote(false),
        "198.51.100.3:53".parse().unwrap(),
        remote(true),
    ] {
        let mut out = [0u8; 2048];
        let n = stack.udp_send(id, dst, b"query", &mut out).unwrap();
        let ip = verify_packet(&out[..n], wire::PROTO_UDP);
        let (source, target, payload) = wire::udp::parse(&out[ip.payload.clone()]).unwrap();
        assert!((32768..=65535).contains(&source));
        assert_eq!(target, dst.port());
        assert_eq!(
            &out[ip.payload.start + payload.start..ip.payload.start + payload.end],
            b"query"
        );
        assert_eq!(*port.get_or_insert(source), source);
        let local = SocketAddr::new(ip.src, source);
        let reply = encode_udp(dst, local, b"answer");
        match stack.receive(now, &reply) {
            Rx::Datagram { flow, src, payload } => {
                assert_eq!((flow, src), (id, dst));
                assert_eq!(payload, wire::ip_header_len(dst.is_ipv6()) + 8..reply.len());
                assert_eq!(&reply[payload], b"answer");
            }
            other => panic!("expected borrowed datagram, got {other:?}"),
        }
    }
    assert!(pull(&mut stack, now).is_none());
}

#[test]
fn udp_unbound_is_silent_and_send_errors_respect_output_size_and_mtu() {
    let now = Instant::now();
    let cfg = config();
    let mut stack = Stack::new(cfg.clone(), now);
    let id = stack.udp_bind(Some(5353)).unwrap();
    for v6 in [false, true] {
        let dst = remote(v6);
        let local = SocketAddr::new(
            if v6 {
                cfg.local_v6.unwrap().into()
            } else {
                cfg.local_v4.unwrap().into()
            },
            5354,
        );
        assert_eq!(
            stack.receive(now, &encode_udp(dst, local, b"nobody")),
            Rx::Dropped(DropReason::NoFlow)
        );
        assert!(
            pull(&mut stack, now).is_none(),
            "unbound UDP never generates ICMP"
        );
        let cap = 1420 - wire::ip_header_len(v6) - 8;
        let bytes = pattern(cap);
        let mut out = [0u8; 2048];
        assert_eq!(
            stack.udp_send(id, dst, &bytes, &mut out[..1419]),
            Err(UdpError::BufferTooSmall)
        );
        assert_eq!(stack.udp_send(id, dst, &bytes, &mut out[..1420]), Ok(1420));
        verify_packet(&out[..1420], wire::PROTO_UDP);
        assert_eq!(
            stack.udp_send(id, dst, &pattern(cap + 1), &mut out),
            Err(UdpError::TooLarge)
        );
        assert_eq!(
            stack.udp_send(id, dst, &[], &mut out),
            Ok(wire::ip_header_len(v6) + 8)
        );
    }
}

#[test]
fn udp_ipv4_zero_checksum_is_accepted_but_ipv6_zero_is_rejected() {
    let now = Instant::now();
    let cfg = config();
    let mut stack = Stack::new(cfg.clone(), now);
    let id = stack.udp_bind(Some(5353)).unwrap();
    for v6 in [false, true] {
        let dst = SocketAddr::new(
            if v6 {
                cfg.local_v6.unwrap().into()
            } else {
                cfg.local_v4.unwrap().into()
            },
            5353,
        );
        let mut bytes = encode_udp(remote(v6), dst, b"checksummed");
        let off = wire::ip_header_len(v6);
        bytes[off + 6..off + 8].fill(0);
        let rx = stack.receive(now, &bytes);
        if v6 {
            assert_eq!(rx, Rx::Dropped(DropReason::Checksum));
        } else {
            match rx {
                Rx::Datagram { flow, payload, .. } => {
                    assert_eq!(flow, id);
                    assert_eq!(&bytes[payload], b"checksummed");
                }
                other => panic!("IPv4 zero checksum must be accepted: {other:?}"),
            }
        }
    }
    assert_eq!(stack.stats().drops[DropReason::Checksum as usize], 1);
}

#[test]
fn invalid_tcp_checksum_never_mutates_state_or_acknowledges_data() {
    for v6 in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let peer = open(&mut stack, &mut now, remote(v6), true, true);
        assert_eq!(stack.tcp_write(peer.id, b"outstanding"), Ok(11));
        let sent = pull(&mut stack, now).unwrap();
        let before = format!("{:?}", stack.tcp_stats(peer.id).unwrap());
        for flags in [tcp::ACK, tcp::RST | tcp::ACK, tcp::SYN | tcp::ACK] {
            let mut h = peer.header(now, sent.end());
            h.flags = flags;
            let mut bytes = peer.packet(&h, b"bad bytes");
            bytes[wire::ip_header_len(v6) + 16] ^= 1;
            assert_eq!(
                stack.receive(now, &bytes),
                Rx::Dropped(DropReason::Checksum)
            );
        }
        assert_eq!(format!("{:?}", stack.tcp_stats(peer.id).unwrap()), before);
        assert_eq!(stack.tcp_state(peer.id), Some(TcpState::Established));
        assert_eq!(
            stack.tcp_read(peer.id, &mut [0; 10]),
            Err(StreamError::WouldBlock)
        );
        assert!(events(&mut stack, peer.id).is_empty());
        assert!(pull(&mut stack, now).is_none());
        assert_eq!(stack.stats().drops[DropReason::Checksum as usize], 3);
        let h = peer.header(now, sent.end());
        assert_eq!(stack.receive(now, &peer.packet(&h, b"valid")), Rx::Consumed);
        let ack = pull(&mut stack, now).unwrap();
        assert_eq!(ack.h.ack, peer.next.wrapping_add(5));
        assert_eq!(stack.tcp_stats(peer.id).unwrap().outstanding_bytes, 0);
        let mut out = [0; 5];
        assert_eq!(stack.tcp_read(peer.id, &mut out), Ok(5));
        assert_eq!(&out, b"valid");
    }
}

#[test]
fn ipv4_and_ipv6_fragments_are_counted_without_tcp_state_mutation() {
    for v6 in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let peer = open(&mut stack, &mut now, remote(v6), true, true);
        let original = peer.packet(&peer.header(now, peer.start), b"fragment");
        for more in [false, true] {
            let mut bytes = original.clone();
            if v6 {
                let upper = bytes.split_off(40);
                bytes[6] = 44;
                let len = (upper.len() + 8) as u16;
                bytes[4..6].copy_from_slice(&len.to_be_bytes());
                bytes.extend_from_slice(&[wire::PROTO_TCP, 0, 0, u8::from(more), 0, 0, 0, 1]);
                bytes.extend_from_slice(&upper);
            } else {
                bytes[6..8].copy_from_slice(&(if more { 0x2000u16 } else { 1u16 }).to_be_bytes());
                bytes[10..12].fill(0);
                let sum = checksum(&bytes[..20]);
                bytes[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            assert_eq!(
                stack.receive(now, &bytes),
                Rx::Dropped(DropReason::Fragment)
            );
        }
        assert_eq!(stack.stats().drops[DropReason::Fragment as usize], 2);
        assert_eq!(stack.tcp_state(peer.id), Some(TcpState::Established));
        assert_eq!(
            stack.tcp_read(peer.id, &mut [0; 10]),
            Err(StreamError::WouldBlock)
        );
        assert!(pull(&mut stack, now).is_none());
    }
}

fn unreachable(src: IpAddr, dst: IpAddr, quote: &[u8]) -> Vec<u8> {
    let quote = &quote[..quote.len().min(wire::ip_header_len(src.is_ipv6()) + 8)];
    let proto = if src.is_ipv6() {
        wire::PROTO_ICMPV6
    } else {
        wire::PROTO_ICMP
    };
    let mut out = vec![0u8; wire::ip_header_len(src.is_ipv6()) + 8 + quote.len()];
    let off = wire::emit_ip_header(&mut out, src, dst, proto, 8 + quote.len()).unwrap();
    out[off] = if src.is_ipv6() { 1 } else { 3 };
    out[off + 1] = 1;
    out[off + 8..].copy_from_slice(quote);
    let mut c = if src.is_ipv6() {
        wire::checksum::Checksum::pseudo(src, dst, proto, out.len() - off)
    } else {
        wire::checksum::Checksum::new()
    };
    c.add(&out[off..]);
    out[off + 2..off + 4].copy_from_slice(&c.finish().to_be_bytes());
    out
}

#[test]
fn icmp_unreachable_with_a_valid_syn_quote_is_a_sticky_connect_error() {
    for v6 in [false, true] {
        let now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let dst = remote(v6);
        let id = stack.tcp_connect(now, dst).unwrap();
        let syn = pull(&mut stack, now).unwrap();
        let msg = unreachable(dst.ip(), syn.ip.src, &syn.bytes);
        assert_eq!(stack.receive(now, &msg), Rx::Consumed);
        assert_eq!(stack.tcp_state(id), Some(TcpState::Closed));
        assert!(events(&mut stack, id).contains(Ready::ERROR | Ready::READ_CLOSED));
        for _ in 0..2 {
            assert_eq!(stack.tcp_write(id, b"x"), Err(StreamError::Unreachable));
            assert_eq!(
                stack.tcp_read(id, &mut [0; 1]),
                Err(StreamError::Unreachable)
            );
        }
        assert!(pull(&mut stack, now).is_none());
    }
}

#[test]
fn icmp_bad_syn_quote_is_ignored_and_established_stream_is_not_aborted() {
    for v6 in [false, true] {
        let mut now = Instant::now();
        let mut stack = Stack::new(config(), now);
        let dst = remote(v6);
        let id = stack.tcp_connect(now, dst).unwrap();
        let syn = pull(&mut stack, now).unwrap();
        for seq in [syn.h.seq.wrapping_sub(1), syn.end()] {
            let mut h = syn.h;
            h.seq = seq;
            let quote = encode_tcp(SocketAddr::new(syn.ip.src, h.src_port), dst, &h, &[]);
            let msg = unreachable(dst.ip(), syn.ip.src, &quote);
            assert_eq!(stack.receive(now, &msg), Rx::Consumed);
            assert_eq!(stack.tcp_state(id), Some(TcpState::SynSent));
            assert!(events(&mut stack, id).is_empty());
        }
        stack.tcp_close(id);
        let peer = open(&mut stack, &mut now, dst, true, true);
        assert_eq!(stack.tcp_write(peer.id, b"live"), Ok(4));
        let data = pull(&mut stack, now).unwrap();
        let msg = unreachable(dst.ip(), peer.local.ip(), &data.bytes);
        assert_eq!(stack.receive(now, &msg), Rx::Consumed);
        assert_eq!(stack.tcp_state(peer.id), Some(TcpState::Established));
        peer.ack(&mut stack, now, data.end());
        assert_eq!(stack.tcp_write(peer.id, b"still live"), Ok(10));
    }
}

#[test]
fn jumbo_mtu_serializes_unaligned_payload_spanning_five_ring_chunks() {
    for v6 in [false, true] {
        let mut cfg = config();
        cfg.mtu = u16::MAX;
        let mut now = Instant::now();
        let mut stack = Stack::new(cfg, now);
        let dst = remote(v6);
        let id = stack.tcp_connect(now, dst).unwrap();
        let syn = pull(&mut stack, now).unwrap();
        assert_eq!(syn.h.options.mss, Some(u16::MAX - if v6 { 60 } else { 40 }));
        let peer = Peer {
            id,
            local: SocketAddr::new(syn.ip.src, syn.h.src_port),
            remote: dst,
            start: syn.end(),
            next: 5001,
            epoch: now,
            timestamps: false,
            echo: 0,
            window: u16::MAX,
        };
        let mut h = peer.header(now, peer.start);
        h.seq = 5000;
        h.flags = tcp::SYN | tcp::ACK;
        h.options.mss = Some(65000);
        h.options.wscale = Some(2);
        now += Duration::from_millis(10);
        assert_eq!(stack.receive(now, &peer.packet(&h, &[])), Rx::Consumed);
        assert_eq!(pull(&mut stack, now).unwrap().h.flags, tcp::ACK);
        peer.ack(&mut stack, now, peer.start);
        let prefix = pattern(1001);
        assert_eq!(stack.tcp_write(id, &prefix), Ok(prefix.len()));
        let first = pull(&mut stack, now).unwrap();
        assert_eq!(first.data(), prefix);
        let payload = pattern(65000);
        assert_eq!(stack.tcp_write(id, &payload), Ok(payload.len()));
        let mut out = vec![0; usize::from(u16::MAX)];
        let n = stack.poll_transmit(now, &mut out).unwrap();
        out.truncate(n);
        let packet = Packet::decode(out);
        assert_eq!(packet.h.seq, first.end());
        assert_eq!(packet.h.ack, peer.next);
        assert_eq!(packet.data(), payload);
        assert_eq!(packet.bytes.len(), 65000 + if v6 { 60 } else { 40 });
        assert_eq!(stack.tcp_stats(id).unwrap().outstanding_bytes, 66001);
        peer.ack(&mut stack, now, packet.end());
        assert_eq!(stack.tcp_stats(id).unwrap().outstanding_bytes, 0);
        assert_eq!(stack.tcp_write(id, b"tail"), Ok(4));
        assert_eq!(pull(&mut stack, now).unwrap().data(), b"tail");
    }
}

#[test]
fn legacy_ipv4_ptb_uses_the_quoted_datagram_length_for_its_next_plateau() {
    let mut now = Instant::now();
    let mut stack = Stack::new(config(), now);
    let peer = open(&mut stack, &mut now, remote(false), false, false);
    let bytes = pattern(500);
    assert_eq!(stack.tcp_write(peer.id, &bytes), Ok(500));
    let original = pull(&mut stack, now).unwrap();
    assert_eq!(original.bytes.len(), 540);
    let mut icmp = [0; 256];
    let n = wire::icmp::emit_packet_too_big(
        &mut icmp,
        peer.remote.ip(),
        peer.local.ip(),
        0,
        &original.bytes,
    )
    .unwrap();
    assert_eq!(stack.receive(now, &icmp[..n]), Rx::Consumed);
    assert_eq!(stack.tcp_stats(peer.id).unwrap().pmtu, 508);
    let first =
        pull(&mut stack, now).expect("old-style PTB must reduce the rejected datagram immediately");
    assert_eq!((first.h.seq, first.data()), (peer.start, &bytes[..468]));
    assert_eq!(first.bytes.len(), 508);
    let tail = pull(&mut stack, now).unwrap();
    assert_eq!((tail.h.seq, tail.data()), (first.end(), &bytes[468..]));
}
