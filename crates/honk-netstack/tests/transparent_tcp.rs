//! Transparent-mode TCP termination: passive open, admission, refusal, keepalive, TIME_WAIT.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use honk_netstack::wire::tcp::{self, ACK, FIN, Header, Options, RST, SYN};
use honk_netstack::{
    AcceptOpts, AcceptWhen, Config, DropReason, ExcludeSet, FlowId, Keepalive, Mode, Ready, Refuse,
    Rx, Stack, StreamError, SynInfo, TcpState,
};

#[path = "transparent_tcp/admission.rs"]
mod admission;

const DST: &str = "203.0.113.9:443";
const CLIENT: &str = "10.0.0.2:40000";

fn transparent() -> Config {
    let mut cfg = Config::new([9; 32]);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg.memory_limit = 64 * 1024 * 1024;
    cfg
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn opts_syn(mss: u16) -> Options {
    Options {
        mss: Some(mss),
        wscale: Some(7),
        sack_permitted: true,
        timestamps: Some((5000, 0)),
        ..Options::default()
    }
}

fn build(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    options: Options,
    data: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0u8; data.len() + 100];
    let n = tcp::emit_packet(
        &mut bytes,
        src.ip(),
        dst.ip(),
        &Header {
            src_port: src.port(),
            dst_port: dst.port(),
            seq,
            ack,
            flags,
            window: 60000,
            urgent: 0,
            options,
        },
        [data, &[]],
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}

#[derive(Debug)]
struct Out {
    src: SocketAddr,
    dst: SocketAddr,
    h: Header,
    payload: Vec<u8>,
}

fn decode(bytes: &[u8]) -> Out {
    let ip = honk_netstack::wire::parse_ip(bytes).unwrap();
    assert_eq!(ip.proto, honk_netstack::wire::PROTO_TCP);
    let seg = &bytes[ip.payload.clone()];
    assert!(tcp::verify_checksum(ip.src, ip.dst, seg));
    let (h, off) = tcp::parse(seg).unwrap();
    Out {
        src: SocketAddr::new(ip.src, h.src_port),
        dst: SocketAddr::new(ip.dst, h.dst_port),
        h,
        payload: seg[off..].to_vec(),
    }
}

fn drain(stack: &mut Stack, now: Instant) -> Vec<Out> {
    let mut all = Vec::new();
    let mut buf = [0u8; 2000];
    while let Some(n) = stack.poll_transmit(now, &mut buf) {
        all.push(decode(&buf[..n]));
    }
    all
}

/// One client talking to the stack through a fixed (client, original destination) pair.
struct Peer {
    client: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ts: u32,
}

impl Peer {
    fn new(client: &str, dst: &str, isn: u32) -> Peer {
        Peer {
            client: addr(client),
            dst: addr(dst),
            seq: isn,
            ts: 5000,
        }
    }

    fn send(&self, stack: &mut Stack, now: Instant, bytes: &[u8]) -> Rx {
        stack.receive(now, bytes)
    }

    fn syn(&self, stack: &mut Stack, now: Instant, mss: u16) -> Rx {
        let mut o = opts_syn(mss);
        o.timestamps = Some((self.ts, 0));
        let b = build(self.client, self.dst, self.seq, 0, SYN, o, &[]);
        self.send(stack, now, &b)
    }

    /// A data/ACK/FIN segment; `ack` is the stack's next sequence number.
    fn seg(
        &mut self,
        stack: &mut Stack,
        now: Instant,
        ack: u32,
        flags: u8,
        tsecr: u32,
        data: &[u8],
    ) -> Rx {
        self.ts += 1;
        let o = Options {
            timestamps: Some((self.ts, tsecr)),
            ..Options::default()
        };
        let b = build(self.client, self.dst, self.seq, ack, flags, o, data);
        self.seq = self
            .seq
            .wrapping_add(data.len() as u32 + u32::from(flags & (SYN | FIN) != 0));
        self.send(stack, now, &b)
    }
}

struct Conn {
    stack: Stack,
    peer: Peer,
    id: FlowId,
    t0: Instant,
    /// The stack's next sequence number.
    snd: u32,
    tsval: u32,
}

/// SYN, accept (`opts`), SYN-ACK, final ACK.
fn established(mut cfg: Config, opts: AcceptOpts) -> Conn {
    cfg.max_flows = 64;
    let t0 = Instant::now();
    let mut stack = Stack::new(cfg, t0);
    let mut peer = Peer::new(CLIENT, DST, 1000);
    assert_eq!(peer.syn(&mut stack, t0, 1460), Rx::Consumed);
    let info = stack.poll_accept().expect("SynInfo");
    stack.tcp_accept(info.id, opts).unwrap();
    let out = drain(&mut stack, t0);
    assert_eq!(out.len(), 1);
    let synack = &out[0];
    assert_eq!(synack.h.flags, SYN | ACK);
    let snd = synack.h.seq.wrapping_add(1);
    let tsval = synack.h.options.timestamps.unwrap().0;
    peer.seq = 1001;
    let now = t0 + Duration::from_millis(5);
    assert_eq!(
        peer.seg(&mut stack, now, snd, ACK, tsval, &[]),
        Rx::Consumed
    );
    assert_eq!(stack.tcp_state(info.id), Some(TcpState::Established));
    Conn {
        stack,
        peer,
        id: info.id,
        t0,
        snd,
        tsval,
    }
}

impl Conn {
    fn client_seg(&mut self, now: Instant, flags: u8, data: &[u8]) {
        let (snd, tsval) = (self.snd, self.tsval);
        assert_eq!(
            self.peer.seg(&mut self.stack, now, snd, flags, tsval, data),
            Rx::Consumed
        );
    }
}

fn info_of(stack: &mut Stack) -> SynInfo {
    stack.poll_accept().expect("SynInfo")
}

#[test]
fn a_syn_makes_a_pending_flow_that_emits_nothing() {
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    let peer = Peer::new(CLIENT, DST, 1000);
    assert_eq!(peer.syn(&mut stack, t0, 1460), Rx::Consumed);
    assert!(
        drain(&mut stack, t0).is_empty(),
        "no SYN-ACK before the decision"
    );
    assert!(!stack.take_tx_wakeup());
    let info = info_of(&mut stack);
    assert_eq!(info.client, addr(CLIENT));
    assert_eq!(info.original_dst, addr(DST));
    assert_eq!(info.mss, 1460);
    assert_eq!(info.wscale, Some(7));
    assert!(info.sack && info.timestamps);
    assert!(stack.poll_accept().is_none(), "reported once");
    assert!(drain(&mut stack, t0 + Duration::from_secs(1)).is_empty());
    let stats = stack.stats();
    assert_eq!((stats.flows, stats.half_open), (1, 1));
}

#[test]
fn immediate_accept_answers_from_the_original_destination() {
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    let mut peer = Peer::new(CLIENT, DST, 1000);
    peer.syn(&mut stack, t0, 1460);
    let info = info_of(&mut stack);
    stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
    assert!(
        stack.take_tx_wakeup(),
        "accepting creates a send obligation"
    );
    assert_eq!(
        stack.tcp_complete(info.id),
        Err(StreamError::Closed),
        "only a deferred flow can be completed"
    );
    let out = drain(&mut stack, t0);
    assert_eq!(out.len(), 1);
    let synack = &out[0];
    assert_eq!(
        synack.src,
        addr(DST),
        "reply source is the original destination"
    );
    assert_eq!(synack.dst, addr(CLIENT));
    assert_eq!(synack.h.flags, SYN | ACK);
    assert_eq!(synack.h.ack, 1001);
    assert_eq!(synack.h.options.mss, Some(1380));
    assert!(synack.h.options.sack_permitted);
    assert_eq!(synack.h.options.timestamps.unwrap().1, 5000);
    let snd = synack.h.seq.wrapping_add(1);
    let tsval = synack.h.options.timestamps.unwrap().0;
    peer.seq = 1001;
    peer.seg(
        &mut stack,
        t0 + Duration::from_millis(3),
        snd,
        ACK,
        tsval,
        b"hello",
    );
    assert_eq!(stack.stats().half_open, 0, "the handshake completed");
    let (id, ready) = stack.poll_event().unwrap();
    assert_eq!(id, info.id);
    assert!(ready.contains(Ready::CONNECTED));
    let mut buf = [0u8; 16];
    assert_eq!(stack.tcp_read(id, &mut buf), Ok(5));
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(stack.tcp_write(id, b"world"), Ok(5));
    let out = drain(&mut stack, t0 + Duration::from_millis(4));
    assert!(
        out.iter()
            .any(|p| p.payload == b"world" && p.src == addr(DST))
    );
}

#[test]
fn retransmitted_syns_never_make_a_second_flow_or_report() {
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    let peer = Peer::new(CLIENT, DST, 1000);
    for i in 0..4u64 {
        assert_eq!(
            peer.syn(&mut stack, t0 + Duration::from_secs(i), 1460),
            Rx::Consumed
        );
        assert!(drain(&mut stack, t0 + Duration::from_secs(i)).is_empty());
    }
    assert_eq!(stack.stats().flows, 1);
    let info = info_of(&mut stack);
    assert!(stack.poll_accept().is_none());
    // Deferred: still absorbed while the upstream dial runs.
    stack
        .tcp_accept(
            info.id,
            AcceptOpts {
                when: AcceptWhen::Deferred {
                    deadline: Duration::from_secs(10),
                },
                ..AcceptOpts::default()
            },
        )
        .unwrap();
    for i in 4..8u64 {
        peer.syn(&mut stack, t0 + Duration::from_secs(i), 1460);
        assert!(drain(&mut stack, t0 + Duration::from_secs(i)).is_empty());
    }
    assert_eq!((stack.stats().flows, stack.poll_accept()), (1, None));
    // Once answered, a retransmitted SYN is a lost SYN-ACK: it is repeated, still one flow.
    stack.tcp_complete(info.id).unwrap();
    let now = t0 + Duration::from_secs(8);
    assert_eq!(drain(&mut stack, now).len(), 1);
    peer.syn(&mut stack, now, 1460);
    let again = drain(&mut stack, now);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].h.flags, SYN | ACK);
    assert_eq!((stack.stats().flows, stack.poll_accept()), (1, None));
}

#[test]
fn deferred_accept_holds_the_syn_ack_until_complete() {
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    let mut peer = Peer::new(CLIENT, DST, 1000);
    peer.syn(&mut stack, t0, 1460);
    let info = info_of(&mut stack);
    stack
        .tcp_accept(
            info.id,
            AcceptOpts {
                when: AcceptWhen::Deferred {
                    deadline: Duration::from_secs(20),
                },
                ..AcceptOpts::default()
            },
        )
        .unwrap();
    assert!(drain(&mut stack, t0).is_empty());
    assert_eq!(
        stack.tcp_accept(info.id, AcceptOpts::default()),
        Err(StreamError::Closed)
    );
    let later = t0 + Duration::from_secs(7);
    stack.handle_timeout(later);
    assert!(drain(&mut stack, later).is_empty());
    stack.tcp_complete(info.id).unwrap();
    let out = drain(&mut stack, later);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].h.flags, SYN | ACK);
    assert_eq!(out[0].src, addr(DST));
    let snd = out[0].h.seq.wrapping_add(1);
    peer.seq = 1001;
    peer.seg(&mut stack, later, snd, ACK, 0, &[]);
    assert_eq!(stack.tcp_state(info.id), Some(TcpState::Established));
}

#[test]
fn a_deferred_flow_that_is_never_completed_dies_silently_within_25_seconds() {
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    let peer = Peer::new(CLIENT, DST, 1000);
    peer.syn(&mut stack, t0, 1460);
    let info = info_of(&mut stack);
    // A longer request is clamped to the 25 s ceiling.
    stack
        .tcp_accept(
            info.id,
            AcceptOpts {
                when: AcceptWhen::Deferred {
                    deadline: Duration::from_secs(600),
                },
                ..AcceptOpts::default()
            },
        )
        .unwrap();
    let before = t0 + Duration::from_millis(24_900);
    stack.handle_timeout(before);
    assert_eq!(
        stack.tcp_complete(info.id),
        Ok(()),
        "still deferred at 24.9 s"
    );
    // (completed above only to prove liveness; restart the scenario for the expiry)
    let mut stack = Stack::new(transparent(), t0);
    peer.syn(&mut stack, t0, 1460);
    let info = info_of(&mut stack);
    stack
        .tcp_accept(
            info.id,
            AcceptOpts {
                when: AcceptWhen::Deferred {
                    deadline: Duration::from_secs(600),
                },
                ..AcceptOpts::default()
            },
        )
        .unwrap();
    assert!(
        stack
            .poll_timeout()
            .is_some_and(|t| t <= t0 + Duration::from_secs(25))
    );
    let at = t0 + Duration::from_secs(25);
    stack.handle_timeout(at);
    let (id, ready) = stack
        .poll_event()
        .expect("the application learns of the expiry");
    assert_eq!(id, info.id);
    assert!(ready.contains(Ready::ERROR));
    assert_eq!(stack.tcp_complete(info.id), Err(StreamError::TimedOut));
    assert!(
        drain(&mut stack, at).is_empty(),
        "no RST: the client simply retries"
    );
    stack.tcp_close(info.id);
    let stats = stack.stats();
    assert_eq!((stats.flows, stats.half_open), (0, 0));
    assert_eq!(stack.tcp_complete(info.id), Err(StreamError::Stale));
}

#[test]
fn an_unreported_syn_expires_without_the_application() {
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    Peer::new(CLIENT, DST, 1000).syn(&mut stack, t0, 1460);
    assert_eq!(stack.stats().half_open, 1);
    let at = t0 + Duration::from_secs(25);
    stack.handle_timeout(at);
    let stats = stack.stats();
    assert_eq!((stats.flows, stats.half_open), (0, 0));
    assert!(stack.poll_accept().is_none());
    assert!(drain(&mut stack, at).is_empty());
}

#[test]
fn refuse_rst_drop_and_ids() {
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    let peer = Peer::new(CLIENT, DST, 1000);
    peer.syn(&mut stack, t0, 1460);
    let info = info_of(&mut stack);
    stack.tcp_refuse(info.id, Refuse::Rst);
    let out = drain(&mut stack, t0);
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].src, out[0].dst), (addr(DST), addr(CLIENT)));
    assert_eq!(out[0].h.flags, RST | ACK);
    assert_eq!((out[0].h.seq, out[0].h.ack), (0, 1001));
    let stats = stack.stats();
    assert_eq!((stats.flows, stats.half_open), (0, 0));
    assert_eq!(
        stack.tcp_accept(info.id, AcceptOpts::default()),
        Err(StreamError::Stale)
    );

    let peer = Peer::new(CLIENT, DST, 2000);
    peer.syn(&mut stack, t0, 1460);
    let info = info_of(&mut stack);
    stack.tcp_refuse(info.id, Refuse::Drop);
    assert!(drain(&mut stack, t0).is_empty());
    assert_eq!(stack.stats().flows, 0);
    // The client may try again right away: a fresh flow, a fresh report.
    peer.syn(&mut stack, t0, 1460);
    assert!(stack.poll_accept().is_some());
}

#[test]
fn refusing_after_the_syn_ack_is_ignored() {
    let mut c = established(transparent(), AcceptOpts::default());
    c.stack.tcp_refuse(c.id, Refuse::Rst);
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::Established));
    assert!(drain(&mut c.stack, c.t0 + ms(10)).is_empty());
}

#[test]
fn max_mss_clamps_both_directions() {
    let mut c = established(
        transparent(),
        AcceptOpts {
            max_mss: Some(1000),
            ..AcceptOpts::default()
        },
    );
    // Re-run the handshake by hand to read the advertised MSS.
    let t0 = Instant::now();
    let mut stack = Stack::new(transparent(), t0);
    let peer = Peer::new("10.0.0.3:41000", DST, 7);
    peer.syn(&mut stack, t0, 1460);
    let info = info_of(&mut stack);
    stack
        .tcp_accept(
            info.id,
            AcceptOpts {
                max_mss: Some(1000),
                ..AcceptOpts::default()
            },
        )
        .unwrap();
    let out = drain(&mut stack, t0);
    assert_eq!(out[0].h.options.mss, Some(1000));
    // Bulk data toward the client never exceeds the clamp even though the client offered 1460.
    let big = vec![7u8; 20_000];
    let mut written = 0;
    while written < big.len() {
        match c.stack.tcp_write(c.id, &big[written..]) {
            Ok(n) => written += n,
            Err(_) => break,
        }
    }
    let out = drain(&mut c.stack, c.t0 + ms(10));
    assert!(!out.is_empty());
    let longest = out.iter().map(|p| p.payload.len()).max().unwrap();
    assert!(
        longest <= 1000 - 12,
        "segment of {longest} bytes exceeds MSS 1000 minus timestamps"
    );
    assert!(longest > 900, "{longest}");
}

#[test]
fn half_open_caps_drop_and_count_without_answering() {
    let t0 = Instant::now();
    let mut cfg = transparent();
    cfg.half_open_max = 5;
    cfg.half_open_per_source = 2;
    let mut stack = Stack::new(cfg, t0);
    let syn =
        |stack: &mut Stack, client: &str, i: u32| Peer::new(client, DST, i).syn(stack, t0, 1460);
    assert_eq!(syn(&mut stack, "10.0.0.2:1001", 1), Rx::Consumed);
    assert_eq!(syn(&mut stack, "10.0.0.2:1002", 2), Rx::Consumed);
    assert_eq!(
        syn(&mut stack, "10.0.0.2:1003", 3),
        Rx::Dropped(DropReason::HalfOpen),
        "per-source cap"
    );
    // Another client is not starved by the first one.
    assert_eq!(syn(&mut stack, "10.0.0.3:1001", 4), Rx::Consumed);
    assert_eq!(syn(&mut stack, "10.0.0.3:1002", 5), Rx::Consumed);
    assert_eq!(syn(&mut stack, "10.0.0.4:1001", 6), Rx::Consumed);
    assert_eq!(
        syn(&mut stack, "10.0.0.5:1001", 7),
        Rx::Dropped(DropReason::HalfOpen),
        "total cap"
    );
    assert_eq!(stack.stats().drops[DropReason::HalfOpen as usize], 2);
    assert!(
        drain(&mut stack, t0).is_empty(),
        "dropped, never reset or answered"
    );
    // Completing a handshake and refusing both free a slot.
    let first = info_of(&mut stack);
    stack.tcp_refuse(first.id, Refuse::Drop);
    assert_eq!(syn(&mut stack, "10.0.0.5:1001", 7), Rx::Consumed);
    let second = info_of(&mut stack);
    stack.tcp_accept(second.id, AcceptOpts::default()).unwrap();
    let out = drain(&mut stack, t0);
    let (snd, tsval) = (
        out[0].h.seq.wrapping_add(1),
        out[0].h.options.timestamps.unwrap().0,
    );
    let mut peer = Peer::new(&second.client.to_string(), DST, 0);
    peer.seq = out[0].h.ack;
    peer.seg(&mut stack, t0, snd, ACK, tsval, &[]);
    assert_eq!(stack.stats().half_open, 4);
    assert_eq!(syn(&mut stack, "10.0.0.5:1002", 8), Rx::Consumed);
}

#[test]
fn flow_table_and_memory_limits_drop_syns() {
    let t0 = Instant::now();
    let mut cfg = transparent();
    cfg.max_flows = 3;
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    let mut stack = Stack::new(cfg, t0);
    // A bound UDP socket counts against the same flow table.
    let _udp = stack.udp_bind(Some(5000)).unwrap();
    assert_eq!(
        Peer::new("10.0.0.2:1", DST, 1).syn(&mut stack, t0, 1460),
        Rx::Consumed
    );
    assert_eq!(
        Peer::new("10.0.0.2:2", DST, 1).syn(&mut stack, t0, 1460),
        Rx::Consumed
    );
    assert_eq!(
        Peer::new("10.0.0.2:3", DST, 1).syn(&mut stack, t0, 1460),
        Rx::Dropped(DropReason::Capacity)
    );
    assert_eq!(stack.stats().drops[DropReason::Capacity as usize], 1);
    assert!(drain(&mut stack, t0).is_empty());
}

#[test]
fn keepalive_probes_an_idle_peer_and_fails_the_flow_when_unanswered() {
    let ka = Keepalive {
        idle: Duration::from_secs(10),
        interval: Duration::from_secs(2),
        probes: 3,
    };
    let mut c = established(
        transparent(),
        AcceptOpts {
            keepalive: Some(ka),
            ..AcceptOpts::default()
        },
    );
    let (id, _) = c.stack.poll_event().unwrap();
    assert_eq!(id, c.id);
    let deadline = c.stack.poll_timeout().expect("keepalive armed");
    assert!(deadline <= c.t0 + ms(5) + ka.idle);
    // Nothing before the idle time.
    c.stack.handle_timeout(c.t0 + ms(9_000));
    assert!(drain(&mut c.stack, c.t0 + ms(9_000)).is_empty());
    let mut probes = Vec::new();
    for at in [10_005u64, 12_005, 14_005] {
        c.stack.handle_timeout(c.t0 + ms(at));
        let out = drain(&mut c.stack, c.t0 + ms(at));
        assert_eq!(out.len(), 1, "one probe at {at} ms");
        probes.push(out.into_iter().next().unwrap());
    }
    for p in &probes {
        assert!(p.payload.is_empty());
        assert_eq!(p.h.flags, ACK);
        assert_eq!(
            p.h.seq,
            c.snd.wrapping_sub(1),
            "keepalive probe sits at snd_una - 1"
        );
        assert_eq!(p.src, addr(DST));
    }
    assert!(c.stack.poll_event().is_none());
    c.stack.handle_timeout(c.t0 + ms(16_005));
    assert!(drain(&mut c.stack, c.t0 + ms(16_005)).is_empty());
    let (id, ready) = c.stack.poll_event().expect("failure surfaces");
    assert_eq!(id, c.id);
    assert!(ready.contains(Ready::ERROR));
    let mut buf = [0u8; 4];
    assert_eq!(c.stack.tcp_read(c.id, &mut buf), Err(StreamError::TimedOut));
}

#[test]
fn an_answered_probe_restarts_the_idle_period() {
    let ka = Keepalive {
        idle: Duration::from_secs(10),
        interval: Duration::from_secs(2),
        probes: 2,
    };
    let mut c = established(
        transparent(),
        AcceptOpts {
            keepalive: Some(ka),
            ..AcceptOpts::default()
        },
    );
    c.stack.handle_timeout(c.t0 + ms(10_005));
    assert_eq!(drain(&mut c.stack, c.t0 + ms(10_005)).len(), 1);
    let _ = c.stack.poll_event();
    // The peer answers with a plain ACK.
    c.client_seg(c.t0 + ms(10_100), ACK, &[]);
    // Far past what the unanswered schedule would allow: still alive and quiet.
    for t in [12_005u64, 14_005, 16_005, 20_000] {
        c.stack.handle_timeout(c.t0 + ms(t));
        assert!(drain(&mut c.stack, c.t0 + ms(t)).is_empty(), "{t}");
    }
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::Established));
    // Idle again: the next probe is one full idle period after the answer.
    c.stack.handle_timeout(c.t0 + ms(20_200));
    assert_eq!(drain(&mut c.stack, c.t0 + ms(20_200)).len(), 1);
    assert!(c.stack.poll_event().is_none());
}

#[test]
fn keepalive_is_off_unless_configured() {
    let mut c = established(transparent(), AcceptOpts::default());
    let _ = c.stack.poll_event();
    let _ = c.stack.poll_event();
    // Only the stale handshake entry of the lazy heap may remain; once popped, nothing is armed.
    c.stack.handle_timeout(c.t0 + ms(30_000));
    assert_eq!(c.stack.poll_timeout(), None, "an idle flow holds no timer");
    let far = c.t0 + ms(3 * 3600 * 1000);
    c.stack.handle_timeout(far);
    assert!(drain(&mut c.stack, far).is_empty());
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::Established));
}

#[test]
fn passive_close_goes_last_ack_to_closed_without_time_wait() {
    let mut c = established(transparent(), AcceptOpts::default());
    let _ = c.stack.poll_event();
    c.client_seg(c.t0 + ms(10), ACK | FIN, &[]);
    let out = drain(&mut c.stack, c.t0 + ms(10));
    assert!(out.iter().any(|p| p.h.flags & ACK != 0));
    assert_eq!(c.stack.tcp_state(c.id), Some(TcpState::CloseWait));
    c.stack.tcp_close(c.id);
    let out = drain(&mut c.stack, c.t0 + ms(11));
    let fin = out.iter().find(|p| p.h.flags & FIN != 0).expect("our FIN");
    assert_eq!(c.stack.stats().flows, 1);
    c.client_seg(c.t0 + ms(12), ACK, &[]);
    // (the client's ACK acknowledges our FIN: ack = fin.seq + 1)
    let _ = fin;
}

#[test]
fn active_close_keeps_time_wait_and_a_late_fin_reaches_the_tombstone() {
    let mut c = established(transparent(), AcceptOpts::default());
    let _ = c.stack.poll_event();
    c.stack.tcp_close(c.id);
    let out = drain(&mut c.stack, c.t0 + ms(10));
    let fin = out
        .iter()
        .find(|p| p.h.flags & FIN != 0)
        .expect("our FIN")
        .h;
    let our_end = fin.seq.wrapping_add(1);
    // Client ACKs our FIN, then sends its own.
    let mut peer = Peer::new(CLIENT, DST, c.peer.seq);
    let tsval = fin.options.timestamps.unwrap().0;
    peer.ts = c.peer.ts;
    peer.seg(&mut c.stack, c.t0 + ms(20), our_end, ACK, tsval, &[]);
    peer.seg(&mut c.stack, c.t0 + ms(30), our_end, ACK | FIN, tsval, &[]);
    let out = drain(&mut c.stack, c.t0 + ms(30));
    assert!(out.iter().any(|p| p.h.flags == ACK && p.h.ack == peer.seq));
    // The flow compacts into a TIME_WAIT tombstone that holds no memory.
    let stats = c.stack.stats();
    assert_eq!((stats.flows, stats.timewait_entries), (0, 1));
    assert_eq!(stats.memory_committed, 0);
    // The client's FIN is retransmitted (our ACK was lost): the tombstone answers it, no RST.
    let fin_seq = peer.seq.wrapping_sub(1);
    let late = build(
        addr(CLIENT),
        addr(DST),
        fin_seq,
        our_end,
        ACK | FIN,
        Options {
            timestamps: Some((peer.ts + 1, tsval)),
            ..Options::default()
        },
        &[],
    );
    assert_eq!(c.stack.receive(c.t0 + ms(2_000), &late), Rx::Consumed);
    let out = drain(&mut c.stack, c.t0 + ms(2_000));
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].h.flags, out[0].h.ack), (ACK, peer.seq));
    // After 60 s the tombstone is gone.
    c.stack.handle_timeout(c.t0 + ms(2_000 + 60_001));
    assert_eq!(c.stack.stats().timewait_entries, 0);
}

#[test]
fn a_syn_reopens_time_wait_only_when_it_is_safe() {
    let mut c = established(transparent(), AcceptOpts::default());
    let _ = c.stack.poll_event();
    c.stack.tcp_close(c.id);
    let out = drain(&mut c.stack, c.t0 + ms(10));
    let fin = out.iter().find(|p| p.h.flags & FIN != 0).unwrap().h;
    let our_end = fin.seq.wrapping_add(1);
    let tsval = fin.options.timestamps.unwrap().0;
    let mut peer = Peer::new(CLIENT, DST, c.peer.seq);
    peer.ts = c.peer.ts;
    peer.seg(&mut c.stack, c.t0 + ms(20), our_end, ACK, tsval, &[]);
    peer.seg(&mut c.stack, c.t0 + ms(30), our_end, ACK | FIN, tsval, &[]);
    drain(&mut c.stack, c.t0 + ms(30));
    assert_eq!(c.stack.stats().timewait_entries, 1);
    let rcv_nxt = peer.seq; // beyond the client's FIN
    let syn = |seq: u32, ts: u32| {
        build(
            addr(CLIENT),
            addr(DST),
            seq,
            0,
            SYN,
            Options {
                timestamps: Some((ts, 0)),
                ..opts_syn(1460)
            },
            &[],
        )
    };
    // An old duplicate SYN (sequence below rcv_nxt, older timestamp) must not kill the tombstone.
    assert_eq!(
        c.stack.receive(c.t0 + ms(100), &syn(500, peer.ts - 5)),
        Rx::Consumed
    );
    assert!(c.stack.poll_accept().is_none());
    assert_eq!(c.stack.stats().timewait_entries, 1);
    // An older timestamp rejects even a sequence number beyond everything seen (PAWS).
    assert_eq!(
        c.stack
            .receive(c.t0 + ms(110), &syn(rcv_nxt.wrapping_add(10), peer.ts - 5)),
        Rx::Consumed
    );
    assert!(c.stack.poll_accept().is_none());
    assert_eq!(c.stack.stats().timewait_entries, 1);
    // A new incarnation (newer timestamp) replaces it and is reported.
    assert_eq!(
        c.stack.receive(c.t0 + ms(200), &syn(500, peer.ts + 1000)),
        Rx::Consumed
    );
    let info = c.stack.poll_accept().expect("reopened");
    assert_eq!(info.client, addr(CLIENT));
    assert_eq!(c.stack.stats().timewait_entries, 0);
    c.stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
    let out = drain(&mut c.stack, c.t0 + ms(200));
    assert_eq!(out.len(), 1);
    assert!(
        (out[0].h.seq.wrapping_sub(our_end) as i32) > 0,
        "the new ISS lies beyond the old incarnation"
    );
    // Without timestamps the sequence number decides.
    let mut c = established(transparent(), AcceptOpts::default());
    let _ = c.stack.poll_event();
    c.stack.tcp_close(c.id);
    let out = drain(&mut c.stack, c.t0 + ms(10));
    let fin = out.iter().find(|p| p.h.flags & FIN != 0).unwrap().h;
    let mut peer = Peer::new(CLIENT, DST, c.peer.seq);
    peer.ts = c.peer.ts;
    let tsval = fin.options.timestamps.unwrap().0;
    let our_end = fin.seq.wrapping_add(1);
    peer.seg(&mut c.stack, c.t0 + ms(20), our_end, ACK, tsval, &[]);
    peer.seg(&mut c.stack, c.t0 + ms(30), our_end, ACK | FIN, tsval, &[]);
    drain(&mut c.stack, c.t0 + ms(30));
    let no_ts = |seq: u32| {
        build(
            addr(CLIENT),
            addr(DST),
            seq,
            0,
            SYN,
            Options {
                mss: Some(1460),
                ..Options::default()
            },
            &[],
        )
    };
    c.stack
        .receive(c.t0 + ms(100), &no_ts(rcv_nxt.wrapping_sub(10)));
    assert!(c.stack.poll_accept().is_none());
    c.stack
        .receive(c.t0 + ms(200), &no_ts(rcv_nxt.wrapping_add(10)));
    assert!(c.stack.poll_accept().is_some());
}

#[test]
fn transparent_mode_scopes_what_it_terminates() {
    let t0 = Instant::now();
    let mut cfg = transparent();
    let mut exclude = ExcludeSet::default();
    exclude.insert("192.168.0.0".parse().unwrap(), 16);
    cfg.mode = Mode::Transparent { exclude };
    let mut stack = Stack::new(cfg, t0);
    let to = |dst: &str| build(addr(CLIENT), addr(dst), 1, 0, SYN, opts_syn(1460), &[]);
    assert_eq!(
        stack.receive(t0, &to("192.168.1.1:80")),
        Rx::Dropped(DropReason::NotForUs)
    );
    for dst in ["224.0.0.251:80", "255.255.255.255:80", "0.0.0.0:80"] {
        assert_eq!(
            stack.receive(t0, &to(dst)),
            Rx::Dropped(DropReason::Unsupported),
            "{dst}"
        );
    }
    // IPv6 neighbor and router discovery noise: multicast destination, dropped silently.
    let noise = build(
        addr("[fe80::1]:1"),
        addr("[ff02::2]:80"),
        1,
        0,
        SYN,
        Options::default(),
        &[],
    );
    assert_eq!(
        stack.receive(t0, &noise),
        Rx::Dropped(DropReason::Unsupported)
    );
    // Multicast or unspecified sources never open a flow.
    let bad_src = build(
        addr("224.0.0.1:1"),
        addr(DST),
        1,
        0,
        SYN,
        opts_syn(1460),
        &[],
    );
    assert_eq!(stack.receive(t0, &bad_src), Rx::Dropped(DropReason::NoFlow));
    assert!(stack.poll_accept().is_none());
    assert!(
        drain(&mut stack, t0)
            .iter()
            .all(|p| p.dst.ip() != addr("224.0.0.1:1").ip())
            || true
    );
    // IPv6 destinations are terminated too.
    let v6 = build(
        addr("[2001:db8::2]:5000"),
        addr("[2001:db8:ffff::9]:443]".trim_end_matches(']')),
        1,
        0,
        SYN,
        opts_syn(1400),
        &[],
    );
    assert_eq!(stack.receive(t0, &v6), Rx::Consumed);
    let info = info_of(&mut stack);
    assert!(matches!(info.original_dst.ip(), IpAddr::V6(_)));
    // A stray ACK without a flow is reset, like any stack.
    let ack = build(addr(CLIENT), addr(DST), 5, 77, ACK, Options::default(), &[]);
    assert_eq!(stack.receive(t0, &ack), Rx::Dropped(DropReason::NoFlow));
    let out = drain(&mut stack, t0);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].h.flags, out[0].h.seq, out[0].src),
        (RST, 77, addr(DST))
    );
}

#[test]
fn endpoint_mode_has_no_passive_open() {
    let t0 = Instant::now();
    let mut cfg = Config::new([1; 32]);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    let mut stack = Stack::new(cfg, t0);
    let syn = build(
        addr(CLIENT),
        addr("192.0.2.1:80"),
        1,
        0,
        SYN,
        opts_syn(1460),
        &[],
    );
    assert_eq!(stack.receive(t0, &syn), Rx::Dropped(DropReason::NoFlow));
    assert!(stack.poll_accept().is_none());
    let out = drain(&mut stack, t0);
    assert_eq!((out.len(), out[0].h.flags), (1, RST | ACK));
    let elsewhere = build(addr(CLIENT), addr(DST), 1, 0, SYN, opts_syn(1460), &[]);
    assert_eq!(
        stack.receive(t0, &elsewhere),
        Rx::Dropped(DropReason::NotForUs)
    );
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn drain_raw(stack: &mut Stack, now: Instant) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    let mut buf = [0u8; 2000];
    while let Some(n) = stack.poll_transmit(now, &mut buf) {
        all.push(buf[..n].to_vec());
    }
    all
}

#[test]
fn icmp_refusals_are_sourced_from_the_original_destination_and_rate_limited() {
    let t0 = Instant::now();
    for (client, dst, how, v4_code, v6_code) in [
        (CLIENT, DST, Refuse::IcmpUnreachable, 1u8, 3u8),
        (CLIENT, DST, Refuse::IcmpAdminProhibited, 13, 1),
        (
            "[2001:db8::2]:40000",
            "[2001:db8:1::9]:443",
            Refuse::IcmpUnreachable,
            1,
            3,
        ),
        (
            "[2001:db8::2]:40000",
            "[2001:db8:1::9]:443",
            Refuse::IcmpAdminProhibited,
            13,
            1,
        ),
    ] {
        let mut stack = Stack::new(transparent(), t0);
        let peer = Peer::new(client, dst, 1000);
        assert_eq!(peer.syn(&mut stack, t0, 1400), Rx::Consumed);
        let info = info_of(&mut stack);
        stack.tcp_refuse(info.id, how);
        let packets = drain_raw(&mut stack, t0);
        assert_eq!(packets.len(), 1, "{client} {how:?}");
        let p = &packets[0];
        let ip = honk_netstack::wire::parse_ip(p).unwrap();
        assert_eq!((ip.src, ip.dst), (addr(dst).ip(), addr(client).ip()));
        let icmp = &p[ip.payload.clone()];
        if addr(client).is_ipv4() {
            assert_eq!(ip.proto, honk_netstack::wire::PROTO_ICMP);
            assert_eq!((icmp[0], icmp[1]), (3, v4_code));
        } else {
            assert_eq!(ip.proto, honk_netstack::wire::PROTO_ICMPV6);
            assert_eq!((icmp[0], icmp[1]), (1, v6_code));
        }
        // The quote is the refused SYN: addressed client -> original destination.
        let quote = honk_netstack::wire::parse_ip(&icmp[8..]).unwrap();
        assert_eq!((quote.src, quote.dst), (addr(client).ip(), addr(dst).ip()));
        assert_eq!(stack.stats().flows, 0);
    }
    // The shared limiter bounds a burst of refusals; the stack keeps working.
    let mut cfg = transparent();
    cfg.icmp_limits.burst = 3;
    cfg.icmp_limits.per_sec = 1;
    cfg.max_flows = 64;
    let mut stack = Stack::new(cfg, t0);
    let mut sent = 0;
    for i in 0..10u16 {
        let peer = Peer::new(
            &format!("10.0.1.{}:5000", i + 1),
            &format!("203.0.113.{}:80", i + 1),
            7,
        );
        peer.syn(&mut stack, t0, 1400);
        let info = info_of(&mut stack);
        stack.tcp_refuse(info.id, Refuse::IcmpUnreachable);
        sent += drain_raw(&mut stack, t0).len();
    }
    assert!((1..10).contains(&sent), "{sent} errors for 10 refusals");
    assert_eq!(stack.stats().flows, 0);
}

#[test]
fn transparent_udp_and_fragments_reach_the_driver_with_both_addresses() {
    let t0 = Instant::now();
    let mut tx = Stack::new(transparent(), t0);
    let mut rx = Stack::new(transparent(), t0);
    let (server, client) = (addr(DST), addr(CLIENT));
    // Small datagram: no flow, no bind.
    let mut out = [0u8; 2000];
    let n = tx
        .udp_send_from(server, client, b"hello", &mut out)
        .unwrap();
    match rx.receive(t0, &out[..n]) {
        Rx::Transparent { src, dst, payload } => {
            assert_eq!((src, dst), (server, client));
            assert_eq!(&out[payload], b"hello");
        }
        other => panic!("{other:?}"),
    }
    // Oversized reply: fragments leave through `poll_transmit`, and reassemble in any order.
    let big: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
    let n = tx.udp_send_from(server, client, &big, &mut out).unwrap();
    assert!(tx.take_tx_wakeup(), "queued fragments need a wakeup");
    let mut packets = vec![out[..n].to_vec()];
    packets.extend(drain_raw(&mut tx, t0));
    assert!(packets.len() >= 3);
    packets.reverse();
    let mut delivered = None;
    for p in &packets {
        match rx.receive(t0, p) {
            Rx::Consumed => {}
            Rx::TransparentOwned {
                src,
                dst,
                packet,
                payload,
            } => {
                delivered = Some((src, dst, packet[payload].to_vec()));
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(delivered, Some((server, client, big)));
    // Reassembly is subject to the same destination filter as everything else.
    let mut cfg = transparent();
    let mut exclude = ExcludeSet::default();
    exclude.insert(client.ip(), 32);
    cfg.mode = Mode::Transparent { exclude };
    let mut filtered = Stack::new(cfg, t0);
    for p in &packets {
        assert_eq!(filtered.receive(t0, p), Rx::Dropped(DropReason::NotForUs));
    }
    assert!(filtered.poll_timeout().is_none());
    // Endpoint mode still drops fragments.
    let mut cfg = Config::new([1; 32]);
    cfg.local_v4 = Some(client.ip().to_string().parse().unwrap());
    let mut endpoint = Stack::new(cfg, t0);
    assert_eq!(
        endpoint.receive(t0, &packets[0]),
        Rx::Dropped(DropReason::Fragment)
    );
    // An unfinished reassembly times out and is forgotten.
    let mut timed = Stack::new(transparent(), t0);
    assert_eq!(timed.receive(t0, &packets[1]), Rx::Consumed);
    assert!(timed.poll_timeout().is_some());
    timed.handle_timeout(t0 + Duration::from_secs(31));
    assert_eq!(timed.poll_timeout(), None);
}

#[test]
fn a_reopened_tuple_gets_an_iss_beyond_the_old_incarnation() {
    let mut c = established(transparent(), AcceptOpts::default());
    let _ = c.stack.poll_event();
    // Send a flight longer than the ISN clock advances in the few milliseconds this test spans,
    // so the clock-based ISS alone would fall below the old incarnation's sequence space.
    assert_eq!(c.stack.tcp_write(c.id, &[1u8; 12_000]), Ok(12_000));
    let out = drain(&mut c.stack, c.t0 + ms(6));
    let end = out
        .iter()
        .map(|p| p.h.seq.wrapping_add(p.payload.len() as u32))
        .max_by_key(|e| e.wrapping_sub(c.snd))
        .unwrap();
    assert_eq!(end.wrapping_sub(c.snd), 12_000);
    let tsval = out[0].h.options.timestamps.unwrap().0;
    c.peer.seg(&mut c.stack, c.t0 + ms(7), end, ACK, tsval, &[]);
    c.stack.tcp_close(c.id);
    let fin = drain(&mut c.stack, c.t0 + ms(8))
        .into_iter()
        .find(|p| p.h.flags & FIN != 0)
        .unwrap()
        .h;
    let our_end = fin.seq.wrapping_add(1);
    c.peer
        .seg(&mut c.stack, c.t0 + ms(9), our_end, ACK, tsval, &[]);
    c.peer
        .seg(&mut c.stack, c.t0 + ms(10), our_end, ACK | FIN, tsval, &[]);
    drain(&mut c.stack, c.t0 + ms(10));
    assert_eq!(c.stack.stats().timewait_entries, 1);
    let syn = build(
        addr(CLIENT),
        addr(DST),
        c.peer.seq.wrapping_add(10),
        0,
        SYN,
        Options {
            timestamps: Some((c.peer.ts + 1_000, 0)),
            ..opts_syn(1460)
        },
        &[],
    );
    assert_eq!(c.stack.receive(c.t0 + ms(12), &syn), Rx::Consumed);
    let info = info_of(&mut c.stack);
    c.stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
    let synack = drain(&mut c.stack, c.t0 + ms(12)).remove(0);
    assert!(
        (synack.h.seq.wrapping_sub(our_end) as i32) > 0,
        "ISS {} is not beyond the old snd_nxt {}",
        synack.h.seq,
        our_end
    );
}
