use crate::xdp::worker::PeerHold;
use honk_netstack::FragmentInfo;
use honk_netstack::wire::PacketView;

#[derive(Debug)]
pub(in crate::control) struct FragmentMacMismatch;

pub(in crate::control) struct FragmentPeer {
    pub(in crate::control) info: FragmentInfo,
    pub(in crate::control) peer: Option<PeerHold>,
    poisoned: bool,
    has_zero: bool,
}

impl FragmentPeer {
    pub(in crate::control) fn new(info: FragmentInfo, peer: Option<PeerHold>) -> Self {
        Self {
            info,
            peer,
            poisoned: false,
            has_zero: false,
        }
    }

    pub(in crate::control) fn observe(
        &mut self,
        info: FragmentInfo,
        is_offset_zero: bool,
        peer: Option<PeerHold>,
    ) -> Result<(), FragmentMacMismatch> {
        self.info = info;
        if self.poisoned {
            return Err(FragmentMacMismatch);
        }
        if let (Some(old), Some(new)) = (&self.peer, &peer)
            && !old.original_path().same_identity(new.original_path())
        {
            self.poisoned = true;
            self.peer = None;
            return Err(FragmentMacMismatch);
        }
        if self.peer.is_none() || (is_offset_zero && !self.has_zero) {
            self.peer = peer;
        }
        self.has_zero |= is_offset_zero;
        Ok(())
    }
}

pub(in crate::control) fn fragment_offset_zero(segments: &[&[u8]]) -> Option<bool> {
    let view = PacketView::new(segments).ok()?;
    let mut base = [0; 40];
    let first = view.len().min(base.len());
    view.copy_to(0..first, &mut base[..first])?;
    match base[0] >> 4 {
        4 if first >= 8 => Some(u16::from_be_bytes([base[6], base[7]]) & 0x1fff == 0),
        6 if first >= 40 => {
            let mut next = base[6];
            let mut offset = 40usize;
            for _ in 0..=8 {
                let mut header = [0; 4];
                view.copy_to(offset..offset.checked_add(4)?, &mut header)?;
                if next == 44 {
                    return Some(u16::from_be_bytes([header[2], header[3]]) & 0xfff8 == 0);
                }
                if !matches!(next, 0 | 43 | 60) {
                    return None;
                }
                next = header[0];
                offset = offset.checked_add((usize::from(header[1]) + 1) * 8)?;
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::routing_input::test_peer;
    use honk_netstack::FragmentIdentity;
    use std::{num::NonZeroU64, time::Instant};

    fn info() -> FragmentInfo {
        FragmentInfo {
            identity: FragmentIdentity {
                src: "192.0.2.1".parse().unwrap(),
                dst: "198.51.100.1".parse().unwrap(),
                proto: 17,
                id: 7,
            },
            original_ingress: Instant::now(),
            incarnation: NonZeroU64::new(1),
        }
    }

    #[test]
    fn fragment_identity_ignores_members_and_qos_but_poison_is_sticky() {
        let info = info();
        for (realm, mac, vid) in [(2, [2; 6], 7), (1, [4; 6], 7), (1, [2; 6], 8)] {
            let mut entry = FragmentPeer::new(info, None);
            entry
                .observe(info, false, Some(test_peer(1, 1, [2; 6], 7)))
                .unwrap();
            entry
                .observe(info, true, Some(test_peer(1, 2, [2; 6], 0xa007)))
                .unwrap();
            let path = entry.peer.as_ref().unwrap().original_path();
            assert_eq!(path.device, 2);
            assert_eq!(path.vlan_tci[0], 0xa007);
            assert!(
                entry
                    .observe(info, false, Some(test_peer(realm, 3, mac, vid)))
                    .is_err()
            );
            assert!(
                entry.peer.is_none(),
                "poison releases its retained return path"
            );
            assert!(
                entry
                    .observe(info, true, Some(test_peer(1, 2, [2; 6], 7)))
                    .is_err()
            );
            assert!(entry.peer.is_none());
        }
    }

    #[test]
    fn fragment_offset_reads_split_ipv6_extension_chain_without_linearizing() {
        let mut packet = [0; 40 + 8 * 9];
        packet[0] = 0x60;
        packet[6] = 60;
        for index in 0..8 {
            packet[40 + index * 8] = if index == 7 { 44 } else { 60 };
        }
        let fragment = 40 + 8 * 8;
        packet[fragment] = 17;
        assert_eq!(
            fragment_offset_zero(&[&packet[..43], &packet[43..]]),
            Some(true)
        );
        packet[fragment + 3] = 8;
        assert_eq!(
            fragment_offset_zero(&[&packet[..43], &packet[43..]]),
            Some(false)
        );
    }
}
