//! Transparent-mode ICMP error generation: fixed reject mapping, RFC 1122/4443 suppression
//! (sing-tun `icmp_error.go`), bounded quotes and Linux-style rate limits.
//!
//! The caller owns the pending refusal: [`IcmpOut::emit`] either writes the packet or reports
//! why not, and a refused `TooSmall` leaves every limiter untouched so the call can be retried.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::wire::{self, icmp::emit_error, ipv6};
use crate::{Stack, UdpError};

/// Quote ceiling: the whole error packet stays within the minimum MTU (RFC 1812 / RFC 4443).
const MAX_ERROR_V4: usize = 576;
const MAX_ERROR_V6: usize = 1280;
/// Fixed ICMP header (type, code, checksum, 4-byte rest).
const ICMP_HEADER: usize = 8;
/// RFC 4443 §3.1 code 1: "communication with destination administratively prohibited".
const V6_ADMIN_PROHIBITED: u8 = 1;

pub(crate) fn quote_limit(v6: bool) -> usize {
    let cap = if v6 { MAX_ERROR_V6 } else { MAX_ERROR_V4 };
    cap - wire::ip_header_len(v6) - ICMP_HEADER
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reject {
    /// Port unreachable: v4 type 3 code 3, v6 type 1 code 4.
    Unreachable,
    /// No route / host unreachable: v4 3/1, v6 1/3.
    HostUnreachable,
    /// Administratively prohibited: v4 3/13, v6 1/1.
    AdminProhibited,
    /// Fragment reassembly timeout: v4 11/1, v6 3/1.
    TimeExceeded,
    /// Transit TTL/hop-limit exhaustion: v4 11/0, v6 3/0.
    HopLimitExceeded,
    /// Frag-needed (v4 3/4) / Packet Too Big (v6 2/0); exempt from rate limits.
    PacketTooBig { mtu: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpEmit {
    /// An error of this many bytes (a complete IP packet) was written to `out`.
    Sent(usize),
    /// Never answered: non-first fragment, unspecified/multicast/broadcast address, an ICMP
    /// error, or an unparseable quote.
    Suppressed,
    /// Dropped by the global or per-target limiter.
    RateLimited,
    /// `out` cannot hold the error; nothing was consumed, retry with a larger buffer.
    TooSmall,
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpLimits {
    /// Global sustained rate in messages per second (Linux `icmp_msgs_per_sec`).
    pub per_sec: u32,
    /// Global burst (Linux `icmp_msgs_burst`).
    pub burst: u32,
    /// Per-target interval (Linux `icmp_ratelimit`).
    pub target_interval: Duration,
    /// Per-target burst in intervals (Linux `XRLIM_BURST_FACTOR`).
    pub target_burst: u32,
    /// Targets remembered; the least recently used is replaced.
    pub max_targets: usize,
}

impl Default for IcmpLimits {
    fn default() -> Self {
        IcmpLimits {
            per_sec: 1000,
            burst: 50,
            target_interval: Duration::from_secs(1),
            target_burst: 6,
            max_targets: 128,
        }
    }
}

struct Target {
    ip: IpAddr,
    /// Microseconds of credit, at most `target_burst * interval`.
    credit: u64,
    last: Instant,
}

pub(crate) struct IcmpOut {
    limits: IcmpLimits,
    /// Global credit in micro-messages (one message costs 1_000_000).
    global: u64,
    global_last: Option<Instant>,
    targets: Vec<Target>,
    pub(crate) suppressed: u64,
    pub(crate) rate_limited: u64,
    pub(crate) sent: u64,
}

impl Default for IcmpOut {
    fn default() -> Self {
        Self::new(IcmpLimits::default())
    }
}

impl IcmpOut {
    pub(crate) fn overhead_bound(limits: IcmpLimits) -> Option<usize> {
        crate::budget::collection_peak::<Target>(limits.max_targets)
    }

    pub(crate) fn new(limits: IcmpLimits) -> IcmpOut {
        IcmpOut {
            global: u64::from(limits.burst) * MSG,
            limits,
            global_last: None,
            targets: Vec::new(),
            suppressed: 0,
            rate_limited: 0,
            sent: 0,
        }
    }

    /// Builds the error for `quoted`, the original IP packet (it may be truncated to its headers
    /// plus a few bytes). The error comes from the original destination, as the transparent
    /// stack answers for it, and goes to the original source.
    pub(crate) fn emit(
        &mut self,
        now: Instant,
        kind: Reject,
        quoted: &[u8],
        out: &mut [u8],
    ) -> IcmpEmit {
        self.emit_from(now, kind, quoted, None, out)
    }

    pub(crate) fn emit_from(
        &mut self,
        now: Instant,
        kind: Reject,
        quoted: &[u8],
        source: Option<IpAddr>,
        out: &mut [u8],
    ) -> IcmpEmit {
        let Some(orig) = inspect(quoted) else {
            self.suppressed += 1;
            return IcmpEmit::Suppressed;
        };
        if orig.suppressed() {
            self.suppressed += 1;
            return IcmpEmit::Suppressed;
        }
        let v6 = orig.src.is_ipv6();
        let ip_len = wire::ip_header_len(v6);
        let quote = &quoted[..quoted.len().min(quote_limit(v6))];
        if out.len() < ip_len + ICMP_HEADER + quote.len() {
            return IcmpEmit::TooSmall;
        }
        let ((ty, code), rest) = match (kind, v6) {
            (Reject::Unreachable, false) => ((3, 3), [0; 4]),
            (Reject::Unreachable, true) => ((1, 4), [0; 4]),
            (Reject::HostUnreachable, false) => ((3, 1), [0; 4]),
            (Reject::HostUnreachable, true) => ((1, 3), [0; 4]),
            (Reject::AdminProhibited, false) => ((3, 13), [0; 4]),
            (Reject::AdminProhibited, true) => ((1, V6_ADMIN_PROHIBITED), [0; 4]),
            (Reject::TimeExceeded, false) => ((11, 1), [0; 4]),
            (Reject::TimeExceeded, true) => ((3, 1), [0; 4]),
            (Reject::HopLimitExceeded, false) => ((11, 0), [0; 4]),
            (Reject::HopLimitExceeded, true) => ((3, 0), [0; 4]),
            (Reject::PacketTooBig { mtu }, false) => {
                let [hi, lo] = u16::try_from(mtu).unwrap_or(u16::MAX).to_be_bytes();
                ((3, 4), [0, 0, hi, lo])
            }
            (Reject::PacketTooBig { mtu }, true) => ((2, 0), mtu.to_be_bytes()),
        };
        if !matches!(kind, Reject::PacketTooBig { .. }) && !self.allow(now, orig.src) {
            self.rate_limited += 1;
            return IcmpEmit::RateLimited;
        }
        match emit_error(
            out,
            source.unwrap_or(orig.dst),
            orig.src,
            (ty, code),
            rest,
            quote,
        ) {
            Some(n) => {
                self.sent += 1;
                IcmpEmit::Sent(n)
            }
            None => IcmpEmit::TooSmall,
        }
    }

    /// Both limiters must agree before either is charged.
    fn allow(&mut self, now: Instant, target: IpAddr) -> bool {
        let l = self.limits;
        let cap = u64::from(l.burst) * MSG;
        let global = match self.global_last {
            None => cap,
            Some(last) => {
                let us = now.saturating_duration_since(last).as_micros() as u64;
                self.global
                    .saturating_add(us.saturating_mul(u64::from(l.per_sec)))
            }
        }
        .min(cap);
        let interval = (l.target_interval.as_micros() as u64).max(1);
        let burst = interval.saturating_mul(u64::from(l.target_burst));
        let slot = self.targets.iter().position(|t| t.ip == target);
        let credit = slot.map_or(burst, |i| {
            let t = &self.targets[i];
            let us = now.saturating_duration_since(t.last).as_micros() as u64;
            t.credit.saturating_add(us).min(burst)
        });
        // The clocks advance even when the message is refused, so credit is never counted twice.
        self.global_last = Some(now);
        self.global = global;
        if let Some(i) = slot {
            self.targets[i].credit = credit;
            self.targets[i].last = now;
        }
        if global < MSG || credit < interval {
            return false;
        }
        self.global = global - MSG;
        let entry = Target {
            ip: target,
            credit: credit - interval,
            last: now,
        };
        match slot {
            Some(i) => self.targets[i] = entry,
            None if self.targets.len() < l.max_targets => self.targets.push(entry),
            None => {
                if let Some(oldest) = self.targets.iter_mut().min_by_key(|t| t.last) {
                    *oldest = entry;
                }
            }
        }
        true
    }
}

const MSG: u64 = 1_000_000;

impl Stack {
    /// Writes the ICMP error `kind` for `original` (the offending IP packet, at least its headers
    /// plus eight bytes) into `out`. `Ok(None)` means it was suppressed or rate limited by design.
    pub(crate) fn send_icmp(
        &mut self,
        now: Instant,
        kind: Reject,
        original: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, UdpError> {
        self.now = now;
        match self.icmp_out.emit(now, kind, original, out) {
            IcmpEmit::Sent(n) => {
                self.counters.tx_packets += 1;
                Ok(Some(n))
            }
            IcmpEmit::Suppressed | IcmpEmit::RateLimited => Ok(None),
            IcmpEmit::TooSmall => Err(UdpError::BufferTooSmall),
        }
    }

    /// Tells the sender of `original` that it exceeds `mtu` (IPv4 fragmentation needed, IPv6
    /// Packet Too Big). Exempt from the ICMP rate limits, as on Linux and gVisor.
    pub fn packet_too_big(
        &mut self,
        now: Instant,
        mtu: u32,
        original: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, UdpError> {
        self.send_icmp(now, Reject::PacketTooBig { mtu }, original, out)
    }
}

struct Original<'a> {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    non_first_fragment: bool,
    l4: &'a [u8],
}

impl Original<'_> {
    fn suppressed(&self) -> bool {
        let special = |a: IpAddr| {
            a.is_unspecified() || a.is_multicast() || a == IpAddr::V4(Ipv4Addr::BROADCAST)
        };
        if self.non_first_fragment || special(self.src) || special(self.dst) {
            return true;
        }
        if self.proto == wire::PROTO_TCP && self.l4.get(13).is_some_and(|flags| flags & 4 != 0) {
            return true;
        }
        match (self.proto, self.l4.first()) {
            // RFC 1122 §3.2.2: never answer an ICMP error. Types beyond the table Linux knows
            // are treated as errors too.
            (wire::PROTO_ICMP, Some(t)) => matches!(t, 3 | 4 | 5 | 11 | 12) || *t > 18,
            // RFC 4443 §2.4(e): types below 128 are errors.
            (wire::PROTO_ICMPV6, Some(t)) => *t < 128,
            (wire::PROTO_ICMP | wire::PROTO_ICMPV6, None) => true,
            _ => false,
        }
    }
}

/// Lenient decoding of an original that may be cut anywhere after its headers.
fn inspect(pkt: &[u8]) -> Option<Original<'_>> {
    match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0F) * 4;
            if pkt.len() < 20 || ihl < 20 || pkt.len() < ihl {
                return None;
            }
            Some(Original {
                src: IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                dst: IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
                proto: pkt[9],
                non_first_fragment: u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1FFF != 0,
                l4: &pkt[ihl..],
            })
        }
        6 => {
            if pkt.len() < ipv6::HEADER_LEN {
                return None;
            }
            let mut walk = ipv6::walk_ext_headers(pkt, ipv6::HEADER_LEN, pkt.len(), pkt[6]).ok()?;
            let (src, dst) = ipv6::addrs(pkt);
            if walk.proto == 44 {
                let h = pkt.get(walk.off..walk.off + ipv6::FRAGMENT_HEADER_LEN)?;
                if u16::from_be_bytes([h[2], h[3]]) & 0xFFF8 != 0 {
                    return None;
                }
                walk = ipv6::walk_ext_headers(
                    pkt,
                    walk.off + ipv6::FRAGMENT_HEADER_LEN,
                    pkt.len(),
                    h[0],
                )
                .ok()?;
                if walk.proto == 44 {
                    return None;
                }
            }
            Some(Original {
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                proto: walk.proto,
                non_first_fragment: false,
                l4: &pkt[walk.off..],
            })
        }
        _ => None,
    }
}

pub(crate) fn quote_metadata(packet: &[u8]) -> Option<crate::transit::Quote> {
    let original = inspect(packet)?;
    if original.suppressed()
        || original.l4.len() < 8
        || (original.proto == wire::PROTO_TCP && original.l4.len() < 14)
    {
        return None;
    }
    let ports = match original.proto {
        wire::PROTO_TCP | wire::PROTO_UDP => Some((
            u16::from_be_bytes(original.l4[..2].try_into().ok()?),
            u16::from_be_bytes(original.l4[2..4].try_into().ok()?),
        )),
        wire::PROTO_ICMP if original.src.is_ipv4() => None,
        wire::PROTO_ICMPV6 if original.src.is_ipv6() => None,
        _ => return None,
    };
    Some(crate::transit::Quote {
        source: original.src,
        destination: original.dst,
        protocol: original.proto,
        ports,
        traffic_class: if original.src.is_ipv4() {
            packet[1]
        } else {
            (packet[0] & 15) << 4 | packet[1] >> 4
        },
        header_len: packet.len() - original.l4.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testutil::*;
    use crate::wire::{icmp, parse_ip, tcp, udp};
    use std::net::SocketAddr;

    fn family() -> [(IpAddr, IpAddr); 2] {
        [(v4(10, 0, 0, 2), v4(198, 51, 100, 7)), (v6(2), v6(7))]
    }

    fn udp_packet(src: IpAddr, dst: IpAddr, payload: usize) -> Vec<u8> {
        let mut b = vec![0u8; 4000];
        let n = udp::emit_packet(
            &mut b,
            SocketAddr::new(src, 4000),
            SocketAddr::new(dst, 53),
            &vec![7; payload],
        )
        .unwrap();
        b.truncate(n);
        b
    }

    fn emit(o: &mut IcmpOut, now: Instant, k: Reject, orig: &[u8]) -> (IcmpEmit, Vec<u8>) {
        let mut out = vec![0u8; 2000];
        let r = o.emit(now, k, orig, &mut out);
        if let IcmpEmit::Sent(n) = r {
            out.truncate(n);
        }
        (r, out)
    }

    #[test]
    fn mapping_addresses_checksum_and_quote_both_families() {
        let now = Instant::now();
        let table = [
            (Reject::Unreachable, [(3, 3), (1, 4)]),
            (Reject::HostUnreachable, [(3, 1), (1, 3)]),
            (Reject::AdminProhibited, [(3, 13), (1, 1)]),
            (Reject::TimeExceeded, [(11, 1), (3, 1)]),
        ];
        for (i, (src, dst)) in family().into_iter().enumerate() {
            let orig = udp_packet(src, dst, 20);
            for (kind, codes) in table {
                let mut o = IcmpOut::default();
                let (r, pkt) = emit(&mut o, now, kind, &orig);
                assert!(matches!(r, IcmpEmit::Sent(_)), "{kind:?} {r:?}");
                let ip = parse_ip(&pkt).unwrap();
                // Answers for the original destination, to the original source.
                assert_eq!((ip.src, ip.dst), (dst, src));
                let msg = &pkt[ip.payload];
                assert_eq!((msg[0], msg[1]), codes[i], "{kind:?}");
                // A valid checksum (the parser rejects a bad one before classifying).
                icmp::parse(ip.src, ip.dst, msg).unwrap();
                assert_eq!(&msg[8..], &orig[..], "short originals are quoted whole");
            }
        }
    }

    #[test]
    fn quote_is_bounded_to_the_minimum_mtu() {
        let now = Instant::now();
        for (src, dst) in family() {
            let orig = udp_packet(src, dst, 3000);
            let (r, pkt) = emit(&mut IcmpOut::default(), now, Reject::Unreachable, &orig);
            assert!(matches!(r, IcmpEmit::Sent(_)));
            assert_eq!(pkt.len(), if src.is_ipv4() { 576 } else { 1280 });
        }
    }

    #[test]
    fn packet_too_big_carries_mtu() {
        let now = Instant::now();
        let (src, dst) = family()[0];
        let (_, p4) = emit(
            &mut IcmpOut::default(),
            now,
            Reject::PacketTooBig { mtu: 1400 },
            &udp_packet(src, dst, 10),
        );
        let ip = parse_ip(&p4).unwrap();
        assert_eq!(
            icmp::parse(ip.src, ip.dst, &p4[ip.payload])
                .unwrap()
                .unwrap()
                .kind,
            icmp::IcmpKind::PacketTooBig { mtu: 1400 }
        );
        let (src, dst) = family()[1];
        let (_, p6) = emit(
            &mut IcmpOut::default(),
            now,
            Reject::PacketTooBig { mtu: 1400 },
            &udp_packet(src, dst, 10),
        );
        let ip = parse_ip(&p6).unwrap();
        assert_eq!(
            icmp::parse(ip.src, ip.dst, &p6[ip.payload])
                .unwrap()
                .unwrap()
                .kind,
            icmp::IcmpKind::PacketTooBig { mtu: 1400 }
        );
    }

    fn assert_suppressed(orig: &[u8], what: &str) {
        let mut o = IcmpOut::default();
        let (r, _) = emit(&mut o, Instant::now(), Reject::Unreachable, orig);
        assert_eq!(r, IcmpEmit::Suppressed, "{what}");
        assert_eq!(o.suppressed, 1);
    }

    #[test]
    fn suppression_rules() {
        let (s4, d4) = family()[0];
        let (s6, d6) = family()[1];
        // Special addresses on either side.
        for special in [v4(0, 0, 0, 0), v4(224, 0, 0, 251), v4(255, 255, 255, 255)] {
            assert_suppressed(&udp_packet(special, d4, 4), "v4 source");
            assert_suppressed(&udp_packet(s4, special, 4), "v4 destination");
        }
        for special in [
            IpAddr::V6("::".parse().unwrap()),
            IpAddr::V6("ff02::1".parse().unwrap()),
        ] {
            assert_suppressed(&udp_packet(special, d6, 4), "v6 source");
            assert_suppressed(&udp_packet(s6, special, 4), "v6 destination");
        }
        // Non-first fragments, v4 and v6.
        let mut frag4 = udp_packet(s4, d4, 40);
        frag4[6] = 0x00;
        frag4[7] = 0x05;
        assert_suppressed(&frag4, "v4 fragment offset 5");
        let mut frag6 = vec![0u8; 40 + 8 + 16];
        frag6[0] = 0x60;
        frag6[6] = 44;
        frag6[8..24].copy_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        frag6[24..40].copy_from_slice(&"fd00::7".parse::<std::net::Ipv6Addr>().unwrap().octets());
        frag6[40] = wire::PROTO_UDP;
        frag6[42..44].copy_from_slice(&(5u16 << 3).to_be_bytes());
        assert_suppressed(&frag6, "v6 fragment offset 5");
        // The first fragment is answered.
        frag6[42..44].copy_from_slice(&1u16.to_be_bytes());
        let (r, _) = emit(
            &mut IcmpOut::default(),
            Instant::now(),
            Reject::Unreachable,
            &frag6,
        );
        assert!(matches!(r, IcmpEmit::Sent(_)));
        // ICMP errors, but not echo.
        for (proto, src, dst, error, query) in [
            (wire::PROTO_ICMP, s4, d4, 3u8, 8u8),
            (wire::PROTO_ICMPV6, s6, d6, 1, 128),
        ] {
            let build = |ty: u8| {
                let mut p = vec![0u8; wire::ip_header_len(src.is_ipv6()) + 8];
                let n = wire::emit_ip_header(&mut p, src, dst, proto, 8).unwrap();
                p[n] = ty;
                p
            };
            assert_suppressed(&build(error), "icmp error");
            let (r, _) = emit(
                &mut IcmpOut::default(),
                Instant::now(),
                Reject::Unreachable,
                &build(query),
            );
            assert!(matches!(r, IcmpEmit::Sent(_)), "echo is answerable");
        }
        // A quote that cannot be decoded.
        assert_suppressed(&[0x45, 0, 0], "truncated header");
    }

    #[test]
    fn first_fragment_inspection_continues_through_extensions_and_truncation() {
        let mut packet = vec![0; 64];
        ipv6::emit(
            &mut packet,
            "fd00::2".parse().unwrap(),
            "fd00::7".parse().unwrap(),
            44,
            24,
        )
        .unwrap();
        ipv6::emit_fragment_header(&mut packet[40..], 60, 0, true, 1).unwrap();
        packet[48] = wire::PROTO_ICMPV6;
        packet[56] = 1;
        assert_suppressed(
            &packet,
            "ICMPv6 error behind Fragment and Destination Options",
        );
        for end in 48..=56 {
            assert_suppressed(&packet[..end], "truncated extension or absent ICMPv6 type");
        }
        packet[56] = 128;
        let (result, _) = emit(
            &mut IcmpOut::default(),
            Instant::now(),
            Reject::Unreachable,
            &packet,
        );
        assert!(
            matches!(result, IcmpEmit::Sent(_)),
            "an inspectable echo is answerable"
        );
        packet[48] = 44;
        assert_suppressed(&packet, "nested Fragment header");
    }

    #[test]
    fn too_small_output_charges_nothing() {
        let (src, dst) = family()[0];
        let orig = udp_packet(src, dst, 20);
        let mut o = IcmpOut::new(IcmpLimits {
            burst: 1,
            ..IcmpLimits::default()
        });
        let now = Instant::now();
        assert_eq!(
            o.emit(now, Reject::Unreachable, &orig, &mut [0; 30]),
            IcmpEmit::TooSmall
        );
        assert!(matches!(
            emit(&mut o, now, Reject::Unreachable, &orig).0,
            IcmpEmit::Sent(_)
        ));
    }

    #[test]
    fn global_bucket_limits_bursts_and_refills() {
        let t0 = Instant::now();
        let mut o = IcmpOut::new(IcmpLimits {
            per_sec: 10,
            burst: 3,
            target_burst: 1000,
            ..IcmpLimits::default()
        });
        let mut sent = 0;
        // Distinct targets, so only the global bucket speaks.
        for i in 0..10u8 {
            let orig = udp_packet(v4(10, 0, 0, i + 1), v4(198, 51, 100, 7), 4);
            sent += matches!(
                emit(&mut o, t0, Reject::Unreachable, &orig).0,
                IcmpEmit::Sent(_)
            ) as u32;
        }
        assert_eq!(sent, 3);
        assert_eq!(o.rate_limited, 7);
        // 10 msgs/s: after 250 ms two more tokens... 2.5, so two messages.
        let t1 = t0 + Duration::from_millis(250);
        let mut sent = 0;
        for i in 0..5u8 {
            let orig = udp_packet(v4(10, 0, 1, i + 1), v4(198, 51, 100, 7), 4);
            sent += matches!(
                emit(&mut o, t1, Reject::Unreachable, &orig).0,
                IcmpEmit::Sent(_)
            ) as u32;
        }
        assert_eq!(sent, 2);
    }

    #[test]
    fn per_target_limit_one_per_second_after_burst() {
        let t0 = Instant::now();
        let mut o = IcmpOut::default();
        let orig = udp_packet(v4(10, 0, 0, 2), v4(198, 51, 100, 7), 4);
        let other = udp_packet(v4(10, 0, 0, 3), v4(198, 51, 100, 7), 4);
        let ok = |r: IcmpEmit| matches!(r, IcmpEmit::Sent(_));
        for _ in 0..6 {
            assert!(ok(emit(&mut o, t0, Reject::HostUnreachable, &orig).0));
        }
        assert_eq!(
            emit(&mut o, t0, Reject::HostUnreachable, &orig).0,
            IcmpEmit::RateLimited
        );
        // Another target is unaffected.
        assert!(ok(emit(&mut o, t0, Reject::HostUnreachable, &other).0));
        // One interval earns exactly one more.
        let t1 = t0 + Duration::from_millis(1000);
        assert!(ok(emit(&mut o, t1, Reject::HostUnreachable, &orig).0));
        assert_eq!(
            emit(&mut o, t1, Reject::HostUnreachable, &orig).0,
            IcmpEmit::RateLimited
        );
        // Frag-needed ignores both limiters.
        for _ in 0..100 {
            assert!(ok(emit(
                &mut o,
                t1,
                Reject::PacketTooBig { mtu: 1280 },
                &orig
            )
            .0));
        }
    }

    #[test]
    fn target_table_is_bounded() {
        let t0 = Instant::now();
        let mut o = IcmpOut::new(IcmpLimits {
            per_sec: 1_000_000,
            burst: 1_000_000,
            max_targets: 4,
            ..IcmpLimits::default()
        });
        for i in 0..50u8 {
            let orig = udp_packet(v4(10, 0, 0, i + 1), v4(198, 51, 100, 7), 4);
            emit(
                &mut o,
                t0 + Duration::from_micros(u64::from(i)),
                Reject::Unreachable,
                &orig,
            );
        }
        assert_eq!(o.targets.len(), 4);
    }

    #[test]
    fn tcp_quote_keeps_ports_and_sequence() {
        let (src, dst) = family()[0];
        let h = tcp::Header {
            src_port: 40_000,
            dst_port: 443,
            seq: 0xDEAD_BEEF,
            ack: 0,
            flags: tcp::SYN,
            window: 100,
            urgent: 0,
            options: tcp::Options::default(),
        };
        let mut b = vec![0u8; 100];
        let n = tcp::emit_packet(&mut b, src, dst, &h, [&[], &[]]).unwrap();
        let (_, pkt) = emit(
            &mut IcmpOut::default(),
            Instant::now(),
            Reject::AdminProhibited,
            &b[..n],
        );
        let ip = parse_ip(&pkt).unwrap();
        let quote = icmp::parse_quoted(&pkt[ip.payload][8..]).unwrap();
        assert_eq!(
            (quote.src_port, quote.dst_port, quote.seq),
            (40_000, 443, Some(0xDEAD_BEEF))
        );
    }
}
