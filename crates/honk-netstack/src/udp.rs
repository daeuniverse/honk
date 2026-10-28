//! Unqueued UDP associations: output goes directly to the caller's packet buffer.

use std::net::SocketAddr;

use crate::flow::Flow;
use crate::wire::{self, IpPacket};
use crate::{BindError, DropReason, FlowId, Rx, Stack, UdpError};

impl Stack {
    pub fn udp_bind(&mut self, local_port: Option<u16>) -> Result<FlowId, BindError> {
        if self.cfg.local_v4.is_none() && self.cfg.local_v6.is_none() {
            return Err(BindError::NoLocalAddress);
        }
        if self.table.active >= self.cfg.max_flows || !self.table.can_insert(None) {
            return Err(BindError::FlowLimit);
        }
        let port = match local_port {
            Some(0) | None => self.allocate_udp_port()?,
            Some(port) => port,
        };
        if self.table.udp.contains_key(&port) {
            return Err(BindError::AddrInUse);
        }
        Ok(self.table.insert(Flow::Udp { port }))
    }

    pub fn udp_send(
        &mut self,
        id: FlowId,
        dst: SocketAddr,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, UdpError> {
        let Some(Flow::Udp { port }) = self.table.get(id) else {
            return Err(UdpError::Stale);
        };
        let local = SocketAddr::new(
            self.local_for(dst.ip()).ok_or(UdpError::NoLocalAddress)?,
            *port,
        );
        let need = wire::ip_header_len(dst.is_ipv6()) + 8 + payload.len();
        if need > usize::from(self.cfg.mtu) || payload.len() > 65527 {
            return Err(UdpError::TooLarge);
        }
        if out.len() < need {
            return Err(UdpError::BufferTooSmall);
        }
        let n = wire::udp::emit_packet(out, local, dst, payload).ok_or(UdpError::BufferTooSmall)?;
        self.counters.tx_packets += 1;
        Ok(n)
    }

    pub fn udp_close(&mut self, id: FlowId) {
        if matches!(self.table.get(id), Some(Flow::Udp { .. })) {
            self.table.remove(id.idx);
        }
    }

    pub(crate) fn receive_udp(&mut self, ip: &IpPacket, packet: &[u8]) -> Rx {
        let dgram = &packet[ip.payload.clone()];
        let (src, dst, payload) = match wire::udp::parse(dgram) {
            Ok(v) => v,
            Err(e) => return self.drop_packet(e.into()),
        };
        if !wire::udp::verify_checksum(ip.src, ip.dst, dgram) {
            return self.drop_packet(DropReason::Checksum);
        }
        let Some(&index) = self.table.udp.get(&dst) else {
            return self.drop_packet(DropReason::NoFlow);
        };
        let id = FlowId {
            idx: index,
            generation: self.table.slots[index as usize].generation,
        };
        Rx::Datagram {
            flow: id,
            src: SocketAddr::new(ip.src, src),
            payload: ip.payload.start + payload.start..ip.payload.start + payload.end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use std::time::Instant;

    #[test]
    fn immediate_udp_transmits_are_counted_only_after_serialization() {
        let mut cfg = Config::new([1; 32]);
        cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
        let mut stack = Stack::new(cfg, Instant::now());
        let id = stack.udp_bind(Some(5555)).unwrap();
        let remote = "198.51.100.1:53".parse().unwrap();
        assert_eq!(
            stack.udp_send(id, remote, b"x", &mut []),
            Err(UdpError::BufferTooSmall)
        );
        assert_eq!(stack.stats().tx_packets, 0);
        assert_eq!(stack.udp_send(id, remote, b"x", &mut [0; 64]), Ok(29));
        assert_eq!(stack.stats().tx_packets, 1);
    }
}
