//! ICMP feedback is accepted only for an outstanding sequence in the quoted flow.

use std::net::SocketAddr;
use std::time::Instant;

use crate::flow::{Flow, FourTuple};
use crate::tcp::{TcpState, seq};
use crate::wire::{self, IpPacket, icmp::IcmpKind};
use crate::{Rx, Stack, StreamError};

impl Stack {
    pub(crate) fn receive_icmp(&mut self, now: Instant, ip: &IpPacket, packet: &[u8]) -> Rx {
        let msg = &packet[ip.payload.clone()];
        let error = match wire::icmp::parse(ip.src, ip.dst, msg) {
            Ok(Some(v)) => v,
            Ok(None) => return Rx::Consumed,
            Err(e) => return self.drop_packet(e.into()),
        };
        let quoted_packet = &msg[error.quoted];
        let Some(quote) = wire::icmp::parse_quoted(quoted_packet) else {
            return Rx::Consumed;
        };
        if quote.proto != wire::PROTO_TCP {
            return Rx::Consumed;
        }
        let Some(quoted_seq) = quote.seq else {
            return Rx::Consumed;
        };
        let tuple = FourTuple {
            local: SocketAddr::new(quote.src, quote.src_port),
            remote: SocketAddr::new(quote.dst, quote.dst_port),
        };
        let Some(&index) = self.table.tcp.get(&tuple) else {
            return Rx::Consumed;
        };
        if let Some(Flow::Tcp(t)) = self.table.slots[index as usize].flow.as_mut() {
            if !seq::ge(quoted_seq, t.snd_una) || !seq::lt(quoted_seq, t.snd_nxt) {
                return Rx::Consumed;
            }
            match error.kind {
                IcmpKind::PacketTooBig { mtu } => {
                    let mtu = if mtu == 0 && quote.src.is_ipv4() {
                        let returned = u16::from_be_bytes([quoted_packet[2], quoted_packet[3]]);
                        // RFC 1191 §5 accounts for old BSD routers adding IHL twice.
                        let corrected = if returned >= t.pmtu {
                            returned.saturating_sub(u16::from(quoted_packet[0] & 15) * 4)
                        } else {
                            returned
                        };
                        next_plateau(corrected.min(t.pmtu))
                    } else {
                        mtu.min(u32::from(u16::MAX)) as u16
                    };
                    t.pmtu(mtu);
                }
                IcmpKind::Unreachable if t.state == TcpState::SynSent => {
                    t.fail(StreamError::Unreachable)
                }
                IcmpKind::Unreachable => {}
            }
        }
        self.sync(index, now);
        Rx::Consumed
    }
}

fn next_plateau(mtu: u16) -> u16 {
    [
        65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
    ]
    .into_iter()
    .find(|&n| n < mtu)
    .unwrap_or(68)
}
