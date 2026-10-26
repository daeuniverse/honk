//! Wire-level retransmission observer. It looks only at the packets a host emits, so it measures
//! any stack the same way and needs no cooperation from it.

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default)]
pub struct WireStats {
    pub tcp_packets: u64,
    pub tcp_payload_bytes: u64,
    /// Payload bytes whose sequence range had already been sent once (RTO, fast and TLP retransmits,
    /// spurious or not). Zero-window probes count too; they are rare enough not to matter.
    pub tcp_retrans_bytes: u64,
}

#[derive(Default)]
pub struct WireTracker {
    /// Per direction of each connection: the sequence number after the highest byte sent so far.
    next_new: HashMap<([u8; 32], u8, u16, u16), u32>,
    pub stats: WireStats,
}

impl WireTracker {
    pub fn observe(&mut self, pkt: &[u8]) {
        let Some(seg) = parse_tcp(pkt) else { return };
        self.stats.tcp_packets += 1;
        self.stats.tcp_payload_bytes += u64::from(seg.payload);
        let next = self.next_new.entry(seg.key).or_insert(seg.seq);
        if seg.syn {
            // A SYN occupies one sequence number; a retransmitted SYN lands on the same value.
            *next = seg.seq.wrapping_add(1);
            return;
        }
        if seg.payload == 0 {
            return;
        }
        let end = seg.seq.wrapping_add(seg.payload);
        let fresh = end.wrapping_sub(*next) as i32;
        let new = if fresh > 0 {
            (fresh as u32).min(seg.payload)
        } else {
            0
        };
        self.stats.tcp_retrans_bytes += u64::from(seg.payload - new);
        if fresh > 0 {
            *next = end;
        }
    }
}

struct Seg {
    key: ([u8; 32], u8, u16, u16),
    seq: u32,
    payload: u32,
    syn: bool,
}

fn parse_tcp(pkt: &[u8]) -> Option<Seg> {
    let version = pkt.first()? >> 4;
    let mut addrs = [0; 32];
    let (ip_hdr, total) = match version {
        4 if pkt.len() >= 20 && pkt[9] == 6 => {
            addrs[..8].copy_from_slice(&pkt[12..20]);
            (
                usize::from(pkt[0] & 0xf) * 4,
                usize::from(u16::from_be_bytes([pkt[2], pkt[3]])),
            )
        }
        // Extension headers are not emitted by any stack under test.
        6 if pkt.len() >= 40 && pkt[6] == 6 => {
            addrs.copy_from_slice(&pkt[8..40]);
            (40, 40 + usize::from(u16::from_be_bytes([pkt[4], pkt[5]])))
        }
        _ => return None,
    };
    let tcp = pkt.get(ip_hdr..total.min(pkt.len()))?;
    if tcp.len() < 20 {
        return None;
    }
    let data_off = usize::from(tcp[12] >> 4) * 4;
    Some(Seg {
        key: (
            addrs,
            version,
            u16::from_be_bytes([tcp[0], tcp[1]]),
            u16::from_be_bytes([tcp[2], tcp[3]]),
        ),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        payload: tcp.len().checked_sub(data_off)? as u32,
        syn: tcp[13] & 0x02 != 0,
    })
}
