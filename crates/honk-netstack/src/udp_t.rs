//! Transparent UDP: stateless receive (every datagram carries `(src, dst)`) and stateless send
//! from any source address, fragmenting replies larger than the MTU like the kernel's reply
//! sockets (no DF, per-datagram identification, up to 64 KiB).
//!
//! Fragmentation continuation: `udp_send_from` writes the first packet into the caller's `out`.
//! The remaining fragments of an oversized datagram are stack state in [`UdpTx`] (the checksummed
//! datagram, copied once) and are pulled with `Stack::poll_udp_frag`, one packet per call, in
//! FIFO order. Nothing is lost when the driver is slow: the queue is bounded, and a send that
//! would exceed it fails with [`UdpError::Busy`] before consuming anything.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crate::icmp_out::Reject;
use crate::offload::{GsoKind, GsoTx, MAX_USO_RX, MAX_USO_TX, RxMeta, Transmit, TxCaps, TxCsum};
use crate::tcp::output::Output;
use crate::wire::{self, IpPacket, ipv4, ipv6};
use crate::{DropReason, MemoryBudget, Rx, Stack, UdpError};

/// Why a transparent UDP datagram is refused (ICMP mapping of the design, §3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpRefuse {
    /// Nothing listens: port unreachable.
    PortUnreachable,
    /// No route to the destination: host unreachable.
    HostUnreachable,
    /// Policy refusal: administratively prohibited.
    AdminProhibited,
}

/// Capacity of datagrams waiting for later fragments, also subject to the shared budget.
pub(crate) const MAX_PENDING_BYTES: usize = 512 * 1024;
const UDP_HEADER: usize = 8;

struct Pending {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    /// UDP header, payload and checksum.
    datagram: Vec<u8>,
    /// Offset of the next fragment within `datagram`.
    next: usize,
    /// Data bytes per fragment (a multiple of 8).
    chunk: usize,
}

impl Pending {
    /// Writes the next fragment and advances; `None` if `out` is too small (nothing changes).
    fn emit(&mut self, out: &mut [u8]) -> Option<usize> {
        let n = self.chunk.min(self.datagram.len() - self.next);
        let more = self.next + n < self.datagram.len();
        let (iplen, extra) = match (self.src, self.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let h = ipv4::emit_fragment(
                    out,
                    s,
                    d,
                    wire::PROTO_UDP,
                    n,
                    (self.id as u16, self.next, more),
                )?;
                (h, 0)
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let h = ipv6::emit(out, s, d, 44, ipv6::FRAGMENT_HEADER_LEN + n)?;
                let f = ipv6::emit_fragment_header(
                    out.get_mut(h..)?,
                    wire::PROTO_UDP,
                    self.next,
                    more,
                    self.id,
                )?;
                (h, f)
            }
            _ => return None,
        };
        let start = iplen + extra;
        out.get_mut(start..start + n)?
            .copy_from_slice(&self.datagram[self.next..self.next + n]);
        self.next += n;
        Some(start + n)
    }

    fn done(&self) -> bool {
        self.next >= self.datagram.len()
    }
}

pub(crate) struct UdpTx {
    queue: VecDeque<Pending>,
    bytes: usize,
    budget: Option<Arc<MemoryBudget>>,
    /// Next IP identification; sequential from a keyed start, so ids never repeat within 2^16
    /// datagrams (IPv4) while still not starting at a guessable value.
    ident: u32,
}

impl Drop for UdpTx {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget
            && self.bytes != 0
        {
            budget.refund(self.bytes);
        }
    }
}

impl UdpTx {
    pub(crate) fn new(secret: &[u8; 32], budget: Option<Arc<MemoryBudget>>) -> UdpTx {
        let h = blake3::keyed_hash(secret, b"honk-netstack udp ident");
        UdpTx {
            queue: VecDeque::new(),
            bytes: 0,
            budget,
            ident: u32::from_le_bytes([
                h.as_bytes()[0],
                h.as_bytes()[1],
                h.as_bytes()[2],
                h.as_bytes()[3],
            ]),
        }
    }

    pub(crate) fn pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Writes the datagram (or its first fragment) to `out`. Errors consume nothing.
    pub(crate) fn send_from(
        &mut self,
        mtu: usize,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, UdpError> {
        if src.is_ipv4() != dst.is_ipv4() {
            return Err(UdpError::FamilyMismatch);
        }
        let v6 = dst.is_ipv6();
        let ip_len = wire::ip_header_len(v6);
        let udp_len = UDP_HEADER + payload.len();
        // 65535 bounds the UDP length field and, for IPv4, the IP total length.
        if udp_len > usize::from(u16::MAX) || (!v6 && ip_len + udp_len > usize::from(u16::MAX)) {
            return Err(UdpError::TooLarge);
        }
        let id = self.ident;
        if ip_len + udp_len <= mtu {
            let packet = ip_len + udp_len;
            if out.len() < packet {
                return Err(UdpError::BufferTooSmall);
            }
            let n = Self::whole(src, dst, payload, id, out, packet)?;
            self.ident = self.ident.wrapping_add(1);
            return Ok(n);
        }
        let frag_extra = if v6 { ipv6::FRAGMENT_HEADER_LEN } else { 0 };
        let chunk = (mtu.saturating_sub(ip_len + frag_extra)) & !7;
        if chunk == 0 {
            return Err(UdpError::TooLarge);
        }
        if !self.queue.is_empty() && self.bytes + udp_len > MAX_PENDING_BYTES {
            return Err(UdpError::Busy);
        }
        if out.len() < ip_len + frag_extra + chunk.min(udp_len) {
            return Err(UdpError::BufferTooSmall);
        }
        if self.budget.as_ref().is_some_and(|b| !b.try_charge(udp_len)) {
            return Err(UdpError::Busy);
        }
        let mut datagram = vec![0u8; udp_len].into_boxed_slice().into_vec();
        wire::udp::emit_datagram(&mut datagram, src, dst, payload)
            .expect("validated UDP length and buffer");
        let mut p = Pending {
            src: src.ip(),
            dst: dst.ip(),
            id,
            datagram,
            next: 0,
            chunk,
        };
        let n = p.emit(out).expect("validated first fragment buffer");
        self.ident = self.ident.wrapping_add(1);
        self.bytes += udp_len;
        self.queue.push_back(p);
        Ok(n)
    }

    /// An unfragmented datagram: no DF, identification set, like a kernel UDP socket.
    fn whole(
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
        id: u32,
        out: &mut [u8],
        packet: usize,
    ) -> Result<usize, UdpError> {
        let udp_len = UDP_HEADER + payload.len();
        let ip_len = packet - udp_len;
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                ipv4::emit_fragment(out, s, d, wire::PROTO_UDP, udp_len, (id as u16, 0, false))
            }
            _ => wire::emit_ip_header(out, src.ip(), dst.ip(), wire::PROTO_UDP, udp_len),
        }
        .ok_or(UdpError::BufferTooSmall)?;
        wire::udp::emit_datagram(&mut out[ip_len..], src, dst, payload)
            .ok_or(UdpError::BufferTooSmall)?;
        Ok(packet)
    }

    /// One USO packet: a single IP header and UDP header over `payload` cut into `size`-byte
    /// datagrams by the driver. The checksum field holds the pseudo-header sum
    /// (`CHECKSUM_PARTIAL`). Errors consume nothing.
    fn send_gso(
        &mut self,
        mtu: usize,
        (src, dst): (SocketAddr, SocketAddr),
        payload: &[u8],
        size: usize,
        out: &mut [u8],
    ) -> Result<Transmit, UdpError> {
        let v6 = dst.is_ipv6();
        let ip_len = wire::ip_header_len(v6);
        let udp_len = UDP_HEADER + payload.len();
        // Every segment is a whole datagram on the wire and must fit the MTU by itself.
        if payload.len().div_ceil(size) > MAX_USO_TX
            || ip_len + UDP_HEADER + size > mtu
            || udp_len > usize::from(u16::MAX)
            || (!v6 && ip_len + udp_len > usize::from(u16::MAX))
        {
            return Err(UdpError::TooLarge);
        }
        let packet = ip_len + udp_len;
        if out.len() < packet {
            return Err(UdpError::BufferTooSmall);
        }
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => ipv4::emit_fragment(
                out,
                s,
                d,
                wire::PROTO_UDP,
                udp_len,
                (self.ident as u16, 0, false),
            ),
            _ => wire::emit_ip_header(out, src.ip(), dst.ip(), wire::PROTO_UDP, udp_len),
        }
        .ok_or(UdpError::BufferTooSmall)?;
        wire::udp::emit_datagram_partial(&mut out[ip_len..], src, dst, payload)
            .ok_or(UdpError::TooLarge)?;
        // IPv4 GSO assigns consecutive IDs to its non-DF datagrams. Reserve the whole run so the
        // next plain or fragmented send cannot reuse one while those datagrams are in flight.
        self.ident = self.ident.wrapping_add(payload.len().div_ceil(size) as u32);
        Ok(Transmit {
            len: packet,
            gso: Some(GsoTx {
                kind: GsoKind::UdpL4,
                size: size as u16,
                hdr_len: (ip_len + UDP_HEADER) as u16,
            }),
            csum: TxCsum::Partial {
                start: ip_len as u16,
                offset: 6,
            },
        })
    }

    /// Next queued fragment. `Blocked` keeps it queued for a larger buffer.
    pub(crate) fn poll(&mut self, out: &mut [u8]) -> Output {
        let Some(p) = self.queue.front_mut() else {
            return Output::None;
        };
        let Some(n) = p.emit(out) else {
            return Output::Blocked;
        };
        if p.done() {
            let p = self.queue.pop_front().expect("front");
            let freed = p.datagram.capacity();
            self.bytes -= freed;
            if let Some(budget) = &self.budget {
                budget.refund(freed);
            }
        }
        Output::Sent(n)
    }

    #[cfg(any(test, feature = "fuzz-checks"))]
    pub(crate) fn check(&self) {
        let sum: usize = self.queue.iter().map(|p| p.datagram.capacity()).sum();
        assert_eq!(sum, self.bytes);
        assert!(self.queue.iter().all(|p| !p.done()));
        assert!(self.queue.len() <= 1 || self.bytes <= MAX_PENDING_BYTES);
    }
}

impl Stack {
    /// Sends `payload` from any source address (a transparent reply comes from the datagram's
    /// original destination). Returns the length of the packet written to `out`; an oversized
    /// datagram is fragmented to the MTU and its remaining fragments are drained with
    /// [`Stack::poll_transmit`], which also sets [`Stack::take_tx_wakeup`].
    pub fn udp_send_from(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, UdpError> {
        let n = self
            .udp_tx
            .send_from(usize::from(self.cfg.mtu), src, dst, payload, out)?;
        self.counters.tx_packets += 1;
        if self.udp_tx.pending() {
            self.tx_wakeup = true;
        }
        Ok(n)
    }

    /// [`Stack::udp_send_from`] for a driver with UDP segmentation offload (`caps.uso4` / `uso6`,
    /// transparent mode): `payload` is the concatenation of datagrams of `size` bytes, the last
    /// possibly shorter, sent as one packet that the driver cuts back into those datagrams
    /// ([`Transmit::gso`], [`TxCsum::Partial`]); boundaries are preserved. At most 64 datagrams,
    /// each fitting the MTU together with its headers, else [`UdpError::TooLarge`]. A payload of
    /// at most one datagram is an ordinary send (fragmenting if over the MTU, like
    /// `udp_send_from`). Without the capability, [`UdpError::Offload`]; nothing is consumed on
    /// error.
    pub fn udp_send_gso_from(
        &mut self,
        (src, dst): (SocketAddr, SocketAddr),
        payload: &[u8],
        size: u16,
        caps: TxCaps,
        out: &mut [u8],
    ) -> Result<Transmit, UdpError> {
        let size = usize::from(size);
        if size == 0 {
            return Err(UdpError::TooLarge);
        }
        if payload.len() <= size {
            return self
                .udp_send_from(src, dst, payload, out)
                .map(Transmit::plain);
        }
        if src.is_ipv4() != dst.is_ipv4() {
            return Err(UdpError::FamilyMismatch);
        }
        if !self.transparent() || !caps.uso(dst.is_ipv6()) {
            return Err(UdpError::Offload);
        }
        let tx = self
            .udp_tx
            .send_gso(usize::from(self.cfg.mtu), (src, dst), payload, size, out)?;
        self.counters.tx_packets += 1;
        Ok(tx)
    }

    /// Answers a refused transparent datagram with the matching ICMP error, written to `out`.
    /// `original` is the datagram's IP packet (headers plus at least eight bytes). `Ok(None)`:
    /// suppressed or rate limited (see `icmp_out`); `Err(BufferTooSmall)` consumes nothing.
    pub fn udp_refuse(
        &mut self,
        now: Instant,
        how: UdpRefuse,
        original: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, UdpError> {
        let kind = match how {
            UdpRefuse::PortUnreachable => Reject::Unreachable,
            UdpRefuse::HostUnreachable => Reject::HostUnreachable,
            UdpRefuse::AdminProhibited => Reject::AdminProhibited,
        };
        self.send_icmp(now, kind, original, out)
    }

    /// Pulls the next fragment of an earlier oversized `udp_send_from`.
    pub(crate) fn poll_udp_frag(&mut self, out: &mut [u8]) -> Output {
        let r = self.udp_tx.poll(out);
        if matches!(r, Output::Sent(_)) {
            self.counters.tx_packets += 1;
        }
        r
    }
}

/// Receives one UDP datagram for any destination. `meta` is the driver's (transparent mode only,
/// see `Stack::receive_with`): a trusted checksum skips verification, a USO super-packet becomes
/// [`Rx::TransparentSplit`].
pub(crate) fn receive_transparent(
    stack: &mut Stack,
    ip: &IpPacket,
    packet: &[u8],
    meta: RxMeta,
) -> Rx {
    let dgram = &packet[ip.payload.clone()];
    let (src, dst, payload) = match wire::udp::parse(dgram) {
        Ok(v) => v,
        Err(e) => return stack.drop_packet(e.into()),
    };
    let (verify, size) = match meta.l4(wire::PROTO_UDP, ip.payload.start, 6) {
        Ok(v) => v,
        Err(reason) => return stack.drop_packet(reason),
    };
    if verify && !wire::udp::verify_checksum(ip.src, ip.dst, dgram) {
        return stack.drop_packet(DropReason::Checksum);
    }
    let (src, dst) = (SocketAddr::new(ip.src, src), SocketAddr::new(ip.dst, dst));
    let payload = ip.payload.start + payload.start..ip.payload.start + payload.end;
    if size == 0 || payload.len() <= usize::from(size) {
        return Rx::Transparent { src, dst, payload };
    }
    if payload.len().div_ceil(usize::from(size)) > MAX_USO_RX {
        return stack.drop_packet(DropReason::Malformed);
    }
    Rx::TransparentSplit {
        src,
        dst,
        payload,
        size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::{Push, Reassembler};
    use crate::wire::testutil::*;
    use crate::wire::{frag, parse_ip, udp};
    use crate::{Config, Rx};
    use std::time::Instant;

    fn stack(mtu: u16) -> Stack {
        let mut cfg = Config::new([9; 32]);
        cfg.mtu = mtu;
        Stack::new(cfg, Instant::now())
    }

    fn addrs(v6: bool) -> (SocketAddr, SocketAddr) {
        if v6 {
            (
                SocketAddr::new(v6_addr(7), 53),
                SocketAddr::new(v6_addr(2), 40_000),
            )
        } else {
            (
                SocketAddr::new(v4(198, 51, 100, 7), 53),
                SocketAddr::new(v4(10, 0, 0, 2), 40_000),
            )
        }
    }

    fn v6_addr(n: u16) -> IpAddr {
        v6(n)
    }

    /// Everything `poll_udp_frag` yields, as separate packets.
    fn drain(s: &mut Stack, first: Vec<u8>) -> Vec<Vec<u8>> {
        let mut all = vec![first];
        let mut out = vec![0u8; 2000];
        while let Output::Sent(n) = s.poll_udp_frag(&mut out) {
            all.push(out[..n].to_vec());
        }
        all
    }

    fn reassemble(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut r = Reassembler::default();
        let now = Instant::now();
        let mut done = None;
        for p in packets {
            match r.push(now, wire::frag::parse(p).unwrap()) {
                Push::Pending => {}
                Push::Complete(c) => done = Some(c.packet),
                Push::Dropped(d) => panic!("dropped {d:?}"),
            }
        }
        r.assert_idle();
        done.expect("never completed")
    }

    #[test]
    fn transparent_reply_comes_from_the_original_destination() {
        for v6 in [false, true] {
            let (orig_dst, client) = addrs(v6);
            let mut s = stack(1400);
            let mut query = vec![0u8; 200];
            let n = udp::emit_packet(&mut query, client, orig_dst, b"query").unwrap();
            let ip = parse_ip(&query[..n]).unwrap();
            let rx = receive_transparent(&mut s, &ip, &query[..n], RxMeta::VERIFY);
            let Rx::Transparent { src, dst, payload } = rx else {
                panic!("{rx:?}")
            };
            assert_eq!((src, dst), (client, orig_dst));
            assert_eq!(&query[payload], b"query");

            // The reply swaps the pair: its source is the address the client addressed.
            let mut out = vec![0u8; 1500];
            let n = s.udp_send_from(dst, src, b"answer", &mut out).unwrap();
            let ip = parse_ip(&out[..n]).unwrap();
            assert_eq!((ip.src, ip.dst), (orig_dst.ip(), client.ip()));
            let rx = receive_transparent(&mut s, &ip, &out[..n], RxMeta::VERIFY);
            let Rx::Transparent { src, dst, payload } = rx else {
                panic!("{rx:?}")
            };
            assert_eq!((src, dst), (orig_dst, client));
            assert_eq!(&out[payload], b"answer");
            assert!(!s.udp_tx.pending());
            assert!(!s.take_tx_wakeup());
            assert_eq!(s.stats().tx_packets, 1);
            // A foreign (full-cone) source works the same.
            let peer = SocketAddr::new(if v6 { v6_addr(99) } else { v4(203, 0, 113, 9) }, 3478);
            let n = s.udp_send_from(peer, client, b"p2p", &mut out).unwrap();
            assert_eq!(parse_ip(&out[..n]).unwrap().src, peer.ip());
        }
    }

    #[test]
    fn receive_checks_checksum_unless_vouched() {
        for v6 in [false, true] {
            let (orig_dst, client) = addrs(v6);
            let mut s = stack(1400);
            let mut p = vec![0u8; 200];
            let n = udp::emit_packet(&mut p, client, orig_dst, b"x").unwrap();
            let ip = parse_ip(&p[..n]).unwrap();
            p[ip.payload.start + 8] ^= 0xFF;
            assert_eq!(
                receive_transparent(&mut s, &ip, &p[..n], RxMeta::VERIFY),
                Rx::Dropped(DropReason::Checksum)
            );
            assert!(matches!(
                receive_transparent(
                    &mut s,
                    &ip,
                    &p[..n],
                    RxMeta {
                        csum: crate::Csum::Valid,
                        gso: None
                    }
                ),
                Rx::Transparent { .. }
            ));
            // A UDP length beyond the IP payload.
            let at = ip.payload.start + 4;
            p[at..at + 2].copy_from_slice(&500u16.to_be_bytes());
            assert_eq!(
                receive_transparent(&mut s, &ip, &p[..n], RxMeta::VERIFY),
                Rx::Dropped(DropReason::Malformed)
            );
        }
    }

    #[test]
    fn oversized_replies_fragment_and_reassemble_both_families() {
        let mtu = 1280usize;
        for v6 in [false, true] {
            let (src, dst) = addrs(v6);
            let ip_len = if v6 { 40 } else { 20 };
            let max = if v6 { 65_527 } else { 65_507 };
            let mut s = stack(mtu as u16);
            let mut seen_ids = Vec::new();
            for len in [
                mtu - ip_len - 8,
                mtu - ip_len - 7,
                2_000,
                8_192,
                30_000,
                max,
            ] {
                let payload = Rng::new(len as u64).bytes(len);
                let mut out = vec![0u8; mtu];
                let n = s.udp_send_from(src, dst, &payload, &mut out).unwrap();
                let fragmented = len > mtu - ip_len - 8;
                assert_eq!(s.udp_tx.pending(), fragmented);
                assert_eq!(s.take_tx_wakeup(), fragmented);
                let packets = drain(&mut s, out[..n].to_vec());
                assert_eq!(packets.len() > 1, fragmented, "{len}");
                assert!(!s.udp_tx.pending());
                s.udp_tx.check();
                assert!(packets.iter().all(|p| p.len() <= mtu));
                if !fragmented {
                    // Unfragmented replies carry no DF and a fresh identification, like a UDP socket.
                    if !v6 {
                        assert_eq!(packets[0][6] & 0x40, 0);
                        seen_ids.push(u16::from_be_bytes([packets[0][4], packets[0][5]]));
                    }
                } else {
                    let mut next = 0;
                    for (i, p) in packets.iter().enumerate() {
                        let f = frag::parse(p).unwrap();
                        assert_eq!(f.offset, next, "fragments are in order");
                        assert_eq!(f.more, i + 1 < packets.len());
                        let extra = if v6 { 8 } else { 0 };
                        if f.more {
                            assert_eq!(f.data.len(), (mtu - ip_len - extra) & !7, "full fragments");
                        }
                        if !v6 {
                            assert_eq!(p[6] & 0x40, 0, "no DF");
                        }
                        next += f.data.len();
                    }
                    if !v6 {
                        let id = u16::from_be_bytes([packets[0][4], packets[0][5]]);
                        assert!(packets.iter().all(|p| p[4..6] == id.to_be_bytes()));
                        seen_ids.push(id);
                    }
                }
                let whole = if fragmented {
                    reassemble(&packets)
                } else {
                    packets[0].clone()
                };
                let ip = parse_ip(&whole).unwrap();
                let rx = receive_transparent(&mut s, &ip, &whole, RxMeta::VERIFY);
                let Rx::Transparent {
                    src: a,
                    dst: b,
                    payload: r,
                } = rx
                else {
                    panic!("{rx:?}")
                };
                assert_eq!((a, b), (src, dst));
                assert_eq!(&whole[r], &payload[..], "len {len}");
            }
            if !v6 {
                let mut sorted = seen_ids.clone();
                sorted.sort_unstable();
                sorted.dedup();
                assert_eq!(sorted.len(), seen_ids.len(), "identifications repeat");
            }
        }
    }

    #[test]
    fn errors_consume_nothing_and_the_queue_is_bounded_without_loss() {
        for v6 in [false, true] {
            let (src, dst) = addrs(v6);
            let mut s = stack(1280);
            let mut out = vec![0u8; 1280];
            let big = vec![1u8; 20_000];
            // Not even the first fragment fits.
            assert_eq!(
                s.udp_send_from(src, dst, &big, &mut out[..1000]),
                Err(UdpError::BufferTooSmall)
            );
            assert_eq!(
                s.udp_send_from(src, dst, b"x", &mut out[..10]),
                Err(UdpError::BufferTooSmall)
            );
            assert!(!s.udp_tx.pending() && !s.take_tx_wakeup());
            assert_eq!(s.stats().tx_packets, 0);
            s.udp_tx.check();
            let too_big = vec![0u8; 65_528];
            assert_eq!(
                s.udp_send_from(src, dst, &too_big, &mut out),
                Err(UdpError::TooLarge)
            );
            let other = SocketAddr::new(if v6 { v4(1, 1, 1, 1) } else { v6_addr(1) }, 9);
            assert_eq!(
                s.udp_send_from(src, other, b"x", &mut out),
                Err(UdpError::FamilyMismatch)
            );

            // Fill the queue: accepted until the byte bound, then Busy, and every accepted
            // datagram still comes out complete and in order.
            let mut accepted = Vec::new();
            let mut firsts = Vec::new();
            let busy = loop {
                let payload = Rng::new(accepted.len() as u64).bytes(60_000);
                match s.udp_send_from(src, dst, &payload, &mut out) {
                    Ok(n) => {
                        firsts.push(out[..n].to_vec());
                        accepted.push(payload);
                    }
                    Err(e) => break e,
                }
                assert!(accepted.len() < 100);
            };
            assert_eq!(busy, UdpError::Busy);
            assert!(
                accepted.len() >= 2 && accepted.len() <= 10,
                "{}",
                accepted.len()
            );
            s.udp_tx.check();
            let mut by_id: Vec<Vec<Vec<u8>>> = Vec::new();
            let mut all = firsts.clone();
            all.extend(drain(&mut s, Vec::new()).into_iter().skip(1));
            // Group by datagram (identification) preserving arrival order.
            for p in all {
                let f = frag::parse(&p).unwrap();
                match by_id
                    .iter_mut()
                    .find(|g| frag::parse(&g[0]).unwrap().id == f.id)
                {
                    Some(g) => g.push(p),
                    None => by_id.push(vec![p]),
                }
            }
            assert_eq!(by_id.len(), accepted.len());
            for (g, payload) in by_id.iter().zip(&accepted) {
                let whole = reassemble(g);
                let ip = parse_ip(&whole).unwrap();
                let (_, _, r) = udp::parse(&whole[ip.payload.clone()]).unwrap();
                assert_eq!(&whole[ip.payload][r], &payload[..]);
            }
            // Room again.
            assert!(s.udp_send_from(src, dst, &big, &mut out).is_ok());
        }
    }

    #[test]
    fn a_small_poll_buffer_keeps_the_fragment() {
        let (src, dst) = addrs(false);
        let mut s = stack(1280);
        let payload = Rng::new(3).bytes(5000);
        let mut out = vec![0u8; 1280];
        let n = s.udp_send_from(src, dst, &payload, &mut out).unwrap();
        let mut tiny = [0u8; 100];
        assert!(matches!(s.poll_udp_frag(&mut tiny), Output::Blocked));
        assert!(s.udp_tx.pending());
        let packets = drain(&mut s, out[..n].to_vec());
        assert_eq!(reassemble(&packets).len(), 20 + 8 + 5000);
        assert!(matches!(s.poll_udp_frag(&mut out), Output::None));
    }

    #[test]
    fn queued_udp_fragments_share_budget_until_fully_sent_or_dropped() {
        for v6 in [false, true] {
            let budget = MemoryBudget::new(3008);
            let funded = || {
                let mut cfg = Config::new([9; 32]);
                cfg.mode = crate::Mode::Transparent {
                    exclude: crate::ExcludeSet::default(),
                };
                cfg.mtu = 1280;
                cfg.shared_budget = Some(budget.clone());
                Stack::new(cfg, Instant::now())
            };
            let mut a = funded();
            let mut b = funded();
            let (src, dst) = addrs(v6);
            let payload = [7; 3000];
            let mut out = [0; 1500];
            let ident = a.udp_tx.ident;
            assert_eq!(
                a.udp_send_from(src, dst, &payload, &mut [0; 1]),
                Err(UdpError::BufferTooSmall)
            );
            assert_eq!(a.udp_tx.ident, ident);
            assert_eq!(budget.used(), 0);
            a.udp_send_from(src, dst, &payload, &mut out).unwrap();
            let retained = a.udp_tx.queue.front().unwrap().datagram.capacity();
            assert_eq!(retained, 3008);
            assert_eq!(budget.used(), retained);
            assert!(matches!(a.poll_udp_frag(&mut [0; 1]), Output::Blocked));
            assert_eq!(budget.used(), retained);
            out.fill(0xA5);
            assert_eq!(
                b.udp_send_from(src, dst, &payload, &mut out),
                Err(UdpError::Busy)
            );
            assert!(out.iter().all(|&byte| byte == 0xA5));
            assert_eq!(budget.used(), retained);
            assert!(!b.udp_tx.pending());
            b.udp_send_from(src, dst, b"small", &mut out).unwrap();
            while let Output::Sent(_) = a.poll_udp_frag(&mut out) {
                assert_eq!(budget.used(), if a.udp_tx.pending() { retained } else { 0 });
                a.udp_tx.check();
            }
            assert_eq!(budget.used(), 0);
            b.udp_send_from(src, dst, &payload, &mut out).unwrap();
            assert_eq!(budget.used(), retained);
            drop(b);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn refusals_answer_for_the_original_destination() {
        let now = Instant::now();
        for v6 in [false, true] {
            let (orig_dst, client) = addrs(v6);
            let mut s = stack(1400);
            let mut query = vec![0u8; 200];
            let n = udp::emit_packet(&mut query, client, orig_dst, b"query").unwrap();
            let query = &query[..n];
            let mut out = vec![0u8; 1500];
            let n = s
                .udp_refuse(now, UdpRefuse::PortUnreachable, query, &mut out)
                .unwrap()
                .unwrap();
            let ip = parse_ip(&out[..n]).unwrap();
            assert_eq!((ip.src, ip.dst), (orig_dst.ip(), client.ip()));
            let msg = &out[ip.payload];
            assert_eq!((msg[0], msg[1]), if v6 { (1, 4) } else { (3, 3) });
            assert_eq!(&msg[8..], query);
            assert_eq!(s.stats().tx_packets, 1);
            // Too small keeps the limiter intact: the same refusal still goes out afterwards.
            assert_eq!(
                s.udp_refuse(now, UdpRefuse::HostUnreachable, query, &mut out[..20]),
                Err(UdpError::BufferTooSmall)
            );
            // A multicast destination is never answered.
            let group = SocketAddr::new(
                if v6 {
                    "ff02::fb".parse().unwrap()
                } else {
                    v4(224, 0, 0, 251)
                },
                5353,
            );
            let mut mc = vec![0u8; 200];
            let n = udp::emit_packet(&mut mc, client, group, b"x").unwrap();
            assert_eq!(
                s.udp_refuse(now, UdpRefuse::AdminProhibited, &mc[..n], &mut out),
                Ok(None)
            );
            // Packet Too Big carries the MTU and ignores the limiter.
            for _ in 0..200 {
                assert!(
                    s.packet_too_big(now, 1280, query, &mut out)
                        .unwrap()
                        .is_some()
                );
            }
        }
    }
}
