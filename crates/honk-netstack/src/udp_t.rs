//! Transparent UDP: stateless receive (every datagram carries `(src, dst)`) and stateless send
//! from any source address, fragmenting replies larger than the MTU like the kernel's reply
//! sockets (no DF, per-datagram identification, up to 64 KiB).
//!
//! Fragmentation continuation: `udp_send_from` writes the first packet into the caller's `out`.
//! The remaining fragments of an oversized datagram are stack state in [`UdpTx`] (the checksummed
//! datagram, copied once) and are pulled with `Stack::poll_udp_frag`, one packet per call, in
//! FIFO order. Nothing is lost when the driver is slow: the queue is bounded, and a send that
//! would exceed it fails with [`UdpError::Busy`] before consuming anything.

#![allow(dead_code)] // consumed by `Stack` once transparent mode is wired in `stack.rs`

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};

use crate::tcp::output::Output;
use crate::wire::{self, IpPacket, ipv4, ipv6};
use crate::{DropReason, Rx, Stack, UdpError};

/// Bytes of datagrams waiting for their later fragments. One datagram is always accepted.
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
    /// Next IP identification; sequential from a keyed start, so ids never repeat within 2^16
    /// datagrams (IPv4) while still not starting at a guessable value.
    ident: u32,
}

impl UdpTx {
    pub(crate) fn new(secret: &[u8; 32]) -> UdpTx {
        let h = blake3::keyed_hash(secret, b"honk-netstack udp ident");
        UdpTx {
            queue: VecDeque::new(),
            bytes: 0,
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

    pub(crate) fn clear(&mut self) {
        self.queue.clear();
        self.bytes = 0;
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
        if out.len() < ip_len + frag_extra + chunk {
            return Err(UdpError::BufferTooSmall);
        }
        if !self.queue.is_empty() && self.bytes + udp_len > MAX_PENDING_BYTES {
            return Err(UdpError::Busy);
        }
        let mut datagram = vec![0u8; udp_len];
        wire::udp::emit_datagram(&mut datagram, src, dst, payload).ok_or(UdpError::TooLarge)?;
        let mut p = Pending {
            src: src.ip(),
            dst: dst.ip(),
            id,
            datagram,
            next: 0,
            chunk,
        };
        let n = p.emit(out).ok_or(UdpError::BufferTooSmall)?;
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
            self.bytes -= p.datagram.len();
        }
        Output::Sent(n)
    }

    #[cfg(any(test, feature = "fuzz-checks"))]
    pub(crate) fn check(&self) {
        let sum: usize = self.queue.iter().map(|p| p.datagram.len()).sum();
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

    /// Pulls the next fragment of an earlier oversized `udp_send_from`.
    pub(crate) fn poll_udp_frag(&mut self, out: &mut [u8]) -> Output {
        let r = self.udp_tx.poll(out);
        if matches!(r, Output::Sent(_)) {
            self.counters.tx_packets += 1;
        }
        r
    }
}

/// Receives one UDP datagram for any destination. `verify_csum` is false only when the driver
/// vouches for the checksum (`Csum::Valid`/`Partial`, transparent mode only).
pub(crate) fn receive_transparent(
    stack: &mut Stack,
    ip: &IpPacket,
    packet: &[u8],
    verify_csum: bool,
) -> Rx {
    let dgram = &packet[ip.payload.clone()];
    let (src, dst, payload) = match wire::udp::parse(dgram) {
        Ok(v) => v,
        Err(e) => return stack.drop_packet(e.into()),
    };
    if verify_csum && !wire::udp::verify_checksum(ip.src, ip.dst, dgram) {
        return stack.drop_packet(DropReason::Checksum);
    }
    Rx::Transparent {
        src: SocketAddr::new(ip.src, src),
        dst: SocketAddr::new(ip.dst, dst),
        payload: ip.payload.start + payload.start..ip.payload.start + payload.end,
    }
}
