//! A `Stack` plus the scripted remote end it talks to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::wire::{self, tcp};
use crate::{Config, FlowId, Stack};

pub(super) const MTU: u16 = 1420;
pub(super) const MAX_PEERS: usize = 12;
/// One fixed-time drain is bounded by the 2 MiB memory limit divided by the smallest positive
/// payload: at IPv4 PMTU 68 a 44-byte TCP header (timestamps/SACK) leaves four bytes.
/// `crash-0abd999e` legitimately emits more than 2048 such packets with a small-MSS peer.
/// Keep a finite bound to catch a scheduler loop without rejecting that valid traffic.
const MAX_DRAIN: usize = 2 * 1024 * 1024 / 4;

fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// The remote end of one TCP flow, as far as the script has to know it.
pub(super) struct Peer {
    pub id: FlowId,
    pub remote: SocketAddr,
    /// Our address and port, known once our SYN has been pulled.
    pub local: Option<SocketAddr>,
    pub iss: u32,
    /// The script's own initial sequence number.
    pub isn: u32,
    /// End of the highest sequence space our output has used.
    pub snd_nxt: u32,
    /// Highest cumulative ACK the script has sent.
    pub acked: u32,
    /// The script's own next sequence number.
    pub next: u32,
    /// Latest timestamp value we sent, echoed back.
    pub echo: u32,
    pub timestamps: bool,
    pub established: bool,
    /// The last data packet we sent, for ICMP quotes.
    pub last_data: Vec<u8>,
}

impl Peer {
    pub fn isn(&self) -> u32 {
        self.isn
    }
}

pub(super) struct Seg<'a> {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub sack: &'a [(u32, u32)],
    pub data: &'a [u8],
}

pub(super) struct World {
    pub stack: Stack,
    pub base: Instant,
    pub now: Instant,
    pub peers: Vec<Peer>,
    pub udp: Option<FlowId>,
    pub pull_flags: u8,
    buf: Vec<u8>,
}

impl World {
    pub fn new() -> World {
        let base = Instant::now();
        let mut cfg = Config::new([0x5a; 32]);
        cfg.mtu = MTU;
        cfg.local_v4 = Some(Ipv4Addr::new(192, 0, 2, 1));
        cfg.local_v6 = Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        cfg.max_flows = 16;
        // Small enough that the shared pool runs out under a few busy flows.
        cfg.memory_limit = 2 * 1024 * 1024;
        // Tighter than the stack's own limit, and exclusive to this world so that "everything
        // returned" can be asserted against the budget itself.
        cfg.shared_budget = Some(crate::MemoryBudget::new(1024 * 1024));
        cfg.tcp_rcv_buf_max = 256 * 1024;
        cfg.tcp_snd_buf_max = 256 * 1024;
        World {
            stack: Stack::new(cfg, base),
            base,
            now: base,
            peers: Vec::new(),
            udp: None,
            pull_flags: 0,
            buf: vec![0; 2048],
        }
    }

    pub fn remote(v6: bool, i: usize) -> SocketAddr {
        if v6 {
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2 + i as u16)),
                443,
            )
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2 + i as u8)), 443)
        }
    }

    pub fn tsval(&self) -> u32 {
        100_000u32.wrapping_add(self.now.duration_since(self.base).as_millis() as u32)
    }

    /// Opens a flow and pulls its SYN so the script learns our port and ISN.
    pub fn connect(&mut self, v6: bool) -> Option<usize> {
        if self.peers.len() >= MAX_PEERS {
            return None;
        }
        let remote = Self::remote(v6, self.peers.len());
        let id = self.stack.tcp_connect(self.now, remote).ok()?;
        assert!(
            self.stack.take_tx_wakeup(),
            "tcp_connect must wake the owner"
        );
        self.peers.push(Peer {
            id,
            remote,
            local: None,
            iss: 0,
            isn: 0x4000_0000u32.wrapping_add(self.peers.len() as u32 * 0x0100_0000),
            snd_nxt: 0,
            acked: 0,
            next: 0,
            echo: 0,
            timestamps: false,
            established: false,
            last_data: Vec::new(),
        });
        self.drain();
        Some(self.peers.len() - 1)
    }

    /// Records what the stack sent so that scripted segments can carry real sequence numbers, and
    /// asserts that everything it emits is a well-formed packet within the MTU.
    fn observe(&mut self, pkt: &[u8]) {
        let ip = wire::parse_ip(pkt).expect("the stack emitted an unparsable IP packet");
        assert!(pkt.len() <= usize::from(MTU), "packet beyond the MTU");
        if ip.proto != wire::PROTO_TCP {
            return;
        }
        let seg = &pkt[ip.payload.clone()];
        assert!(
            tcp::verify_checksum(ip.src, ip.dst, seg),
            "bad output checksum"
        );
        let (h, off) = tcp::parse(seg).expect("the stack emitted an unparsable TCP segment");
        let Some(p) = self
            .peers
            .iter_mut()
            .find(|p| p.remote == SocketAddr::new(ip.dst, h.dst_port))
        else {
            return;
        };
        p.local = Some(SocketAddr::new(ip.src, h.src_port));
        let len = seg.len() - off;
        let end = h
            .seq
            .wrapping_add(len as u32)
            .wrapping_add(u32::from(h.flags & tcp::SYN != 0))
            .wrapping_add(u32::from(h.flags & tcp::FIN != 0));
        if h.flags & tcp::SYN != 0 && h.flags & tcp::ACK == 0 {
            p.iss = h.seq;
            p.snd_nxt = end;
            p.acked = end;
        } else if after(end, p.snd_nxt) {
            p.snd_nxt = end;
        }
        if let Some((val, _)) = h.options.timestamps {
            p.echo = val;
        }
        if len > 0 {
            p.last_data = pkt.to_vec();
        }
    }

    /// Pulls up to `max` packets and returns how many came out.
    pub fn pull(&mut self, max: usize) -> usize {
        if self.pull_flags & 64 != 0 {
            return 0;
        }
        let mut n = 0;
        while n < max {
            let limit = if self.pull_flags & 32 != 0 {
                31
            } else {
                self.buf.len()
            };
            let len = if self.pull_flags & 128 != 0 {
                super::control_transmit(&mut self.stack, self.now, &mut self.buf[..limit])
                    .map(|tx| tx.len)
            } else {
                self.stack.poll_transmit(self.now, &mut self.buf[..limit])
            };
            let Some(len) = len else {
                break;
            };
            let pkt = self.buf[..len].to_vec();
            self.observe(&pkt);
            self.stack.check();
            n += 1;
        }
        n
    }

    /// Everything currently sendable, plus the readiness events.
    pub fn drain(&mut self) {
        let n = self.pull(MAX_DRAIN + 1);
        assert!(n <= MAX_DRAIN, "{n} packets from one drain");
        while self.stack.poll_event().is_some() {}
    }

    /// Lets `d` pass and runs the deadlines that came due.
    pub fn advance(&mut self, d: Duration) {
        self.now += d;
        self.stack.handle_timeout(self.now);
        if let Some(next) = self.stack.poll_timeout() {
            assert!(
                next > self.now,
                "an expired deadline survived handle_timeout"
            );
        }
    }

    pub fn segment(&self, i: usize, s: &Seg) -> Option<Vec<u8>> {
        let p = &self.peers[i];
        let local = p.local?;
        let mut options = tcp::Options::default();
        if p.timestamps {
            options.timestamps = Some((self.tsval(), p.echo));
        }
        for &(l, r) in s.sack {
            options.sack.push(l, r);
        }
        let h = tcp::Header {
            src_port: p.remote.port(),
            dst_port: local.port(),
            seq: s.seq,
            ack: s.ack,
            flags: s.flags,
            window: s.window,
            urgent: 0,
            options,
        };
        let mut out = vec![0; s.data.len() + 160];
        let n = tcp::emit_packet(&mut out, p.remote.ip(), local.ip(), &h, [s.data, &[]])?;
        out.truncate(n);
        Some(out)
    }

    /// Delivers a segment from peer `i`, keeping the script's sequence bookkeeping.
    pub fn deliver(&mut self, i: usize, s: &Seg) {
        let Some(bytes) = self.segment(i, s) else {
            return;
        };
        let p = &mut self.peers[i];
        let end = s
            .seq
            .wrapping_add(s.data.len() as u32)
            .wrapping_add(u32::from(s.flags & tcp::FIN != 0));
        if s.seq == p.next {
            p.next = end;
        }
        if s.flags & tcp::ACK != 0 && !after(s.ack, p.snd_nxt) && after(s.ack, p.acked) {
            p.acked = s.ack;
        }
        self.stack.receive(self.now, &bytes);
    }

    /// The remote's SYN-ACK; options say what it negotiates.
    pub fn syn_ack(&mut self, i: usize, mss: u16, wscale: Option<u8>, sack: bool, ts: bool) {
        let p = &mut self.peers[i];
        let Some(local) = p.local else { return };
        p.next = p.isn().wrapping_add(1);
        p.timestamps = ts;
        p.established = true;
        let h = tcp::Header {
            src_port: p.remote.port(),
            dst_port: local.port(),
            seq: p.isn(),
            ack: p.iss.wrapping_add(1),
            flags: tcp::SYN | tcp::ACK,
            window: u16::MAX,
            urgent: 0,
            options: tcp::Options {
                mss: Some(mss),
                wscale,
                sack_permitted: sack,
                timestamps: ts.then_some((100_000, p.echo)),
                ..tcp::Options::default()
            },
        };
        let mut out = vec![0; 160];
        let n = tcp::emit_packet(&mut out, p.remote.ip(), local.ip(), &h, [&[], &[]])
            .expect("a SYN-ACK fits");
        self.stack.receive(self.now, &out[..n]);
    }

    /// The remote acknowledges everything we sent.
    pub fn ack_all(&mut self, i: usize) {
        let p = &self.peers[i];
        let s = Seg {
            seq: p.next,
            ack: p.snd_nxt,
            flags: tcp::ACK,
            window: u16::MAX,
            sack: &[],
            data: &[],
        };
        self.deliver(i, &s);
    }

    /// In-order data (and optionally the FIN) from the remote.
    pub fn send_data(&mut self, i: usize, data: &[u8], fin: bool) {
        let p = &self.peers[i];
        let s = Seg {
            seq: p.next,
            ack: p.snd_nxt,
            flags: tcp::ACK | if fin { tcp::FIN } else { 0 },
            window: u16::MAX,
            sack: &[],
            data,
        };
        self.deliver(i, &s);
    }

    /// The bound UDP socket's address, as the remote would send to it.
    pub fn udp_local(&self) -> Option<SocketAddr> {
        let Some(crate::flow::Flow::Udp { port }) = self.stack.table.get(self.udp?) else {
            return None;
        };
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            *port,
        ))
    }

    pub fn write(&mut self, i: usize, n: usize) {
        let data: Vec<u8> = (0..n).map(|k| (k % 251) as u8).collect();
        if let Ok(written) = self.stack.tcp_write(self.peers[i].id, &data)
            && written > 0
        {
            assert!(self.stack.take_tx_wakeup(), "tcp_write must wake the owner");
        }
    }

    pub fn read(&mut self, i: usize, n: usize) {
        let mut out = vec![0; n];
        let _ = self.stack.tcp_read(self.peers[i].id, &mut out);
        let _ = self.stack.take_tx_wakeup();
    }

    pub fn shutdown(&mut self, i: usize) {
        if self.stack.tcp_shutdown(self.peers[i].id).is_ok() {
            assert!(
                self.stack.take_tx_wakeup(),
                "tcp_shutdown must wake the owner"
            );
        }
    }

    /// Aborts every handle still open, then lets the silent remote time everything out.
    pub fn finish(&mut self) {
        self.pull_flags = 0;
        for i in 0..self.peers.len() {
            self.stack.tcp_abort(self.peers[i].id);
        }
        if let Some(id) = self.udp.take() {
            self.stack.udp_close(id);
        }
        for _ in 0..96 {
            self.drain();
            self.stack.check();
            let stats = self.stack.stats();
            if stats.flows == 0 && stats.timewait_entries == 0 {
                break;
            }
            self.advance(Duration::from_secs(130));
        }
        self.drain();
        let stats = self.stack.stats();
        assert!(
            stats.flows == 0 && stats.timewait_entries == 0,
            "flows never terminated: {} live, {} TIME_WAIT",
            stats.flows,
            stats.timewait_entries
        );
        self.stack.assert_released();
        while self.stack.poll_event().is_some() {}
        assert!(self.stack.poll_timeout().is_none_or(|t| t > self.now));
    }
}
