use super::*;
use crate::control::netstack::{FragmentPeer, fragment_offset_zero};
use crate::xdp::worker::PeerHold;
use honk_netstack::FragmentInfo;

pub(super) struct FragmentPeers {
    cells: Box<[Option<(Ingress, FragmentPeer)>]>,
    _memory: MemoryReservation,
}

impl RoutedCore {
    pub(crate) fn prepare_fragment_peers(&mut self) -> io::Result<()> {
        if self.fragment_peers.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Core fragment peer storage is already prepared",
            ));
        }
        let count = self
            .core
            .ingresses()
            .len()
            .checked_mul(64 + 16)
            .ok_or_else(|| io::Error::other("Core fragment peer capacity overflow"))?;
        let bytes = count
            .checked_mul(size_of::<Option<(Ingress, FragmentPeer)>>())
            .and_then(|bytes| bytes.checked_add(size_of::<FragmentPeers>()))
            .ok_or_else(|| io::Error::other("Core fragment peer memory overflow"))?;
        let memory = self.budget.reserve(bytes).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Core fragment peer memory capacity",
            )
        })?;
        self.fragment_peers = Some(FragmentPeers {
            cells: (0..count).map(|_| None).collect(),
            _memory: memory,
        });
        Ok(())
    }

    pub(crate) fn receive_segments_with_peer_at(
        &mut self,
        ingress: Ingress,
        ingress_at: Instant,
        service_at: Instant,
        segments: &[&[u8]],
        mut peer: Option<PeerHold>,
    ) -> anyhow::Result<Option<(Packet, Option<PeerHold>)>> {
        self.reap_fragment_peers();
        let (packet, fragment, failure) = match self
            .core
            .receive_segments_with_fragments_at(ingress, ingress_at, service_at, segments)
        {
            Ok((packet, fragment)) => (packet, fragment, None),
            Err(ForwardError::Fragment(error)) => {
                (None, error.fragment, Some(ForwardError::Fragment(error)))
            }
            Err(error) => {
                self.counters.core(&error);
                return Err(error.into());
            }
        };
        if let Some(info) = fragment.filter(|info| info.incarnation.is_some()) {
            let is_offset_zero = fragment_offset_zero(segments).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid fragment header")
            })?;
            let peers = self
                .fragment_peers
                .as_mut()
                .ok_or_else(|| io::Error::other("Core fragment peer storage is not prepared"))?;
            let previous = peers.cells.iter().position(|cell| {
                cell.as_ref().is_some_and(|(owned, entry)| {
                    *owned == ingress && entry.info.incarnation == info.incarnation
                })
            });
            let mut entry = match previous {
                Some(index) => {
                    peers.cells[index]
                        .take()
                        .expect("exact fragment peer incarnation")
                        .1
                }
                None => FragmentPeer::new(info, None),
            };
            let poisoned = entry.observe(info, is_offset_zero, peer.take()).is_err();
            for cell in &mut peers.cells {
                if cell.as_ref().is_some_and(|(owned, retained)| {
                    !self.core.retains_fragment(*owned, retained.info)
                }) {
                    cell.take();
                }
            }
            if packet.is_some() {
                if poisoned {
                    return Ok(None);
                }
                peer = entry.peer;
            } else if self.core.retains_fragment(ingress, info) {
                let cell = peers
                    .cells
                    .iter_mut()
                    .find(|cell| cell.is_none())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::WouldBlock, "Core fragment peer capacity")
                    })?;
                *cell = Some((ingress, entry));
            }
            if poisoned {
                return Ok(None);
            }
        }
        self.reap_fragment_peers();
        match failure {
            Some(error) => {
                self.counters.core(&error);
                Err(error.into())
            }
            None => Ok(self.pin_received(packet).map(|packet| (packet, peer))),
        }
    }

    pub(super) fn fragment_peer(&self, ingress: Ingress, info: FragmentInfo) -> Option<PeerHold> {
        self.fragment_peers
            .as_ref()?
            .cells
            .iter()
            .flatten()
            .find(|(owned, entry)| {
                *owned == ingress
                    && info.incarnation.is_some()
                    && entry.info.incarnation == info.incarnation
            })
            .and_then(|(_, entry)| entry.peer.clone())
    }

    pub(super) fn reap_fragment_peers(&mut self) {
        let core = &self.core;
        if let Some(peers) = &mut self.fragment_peers {
            for cell in &mut peers.cells {
                if cell
                    .as_ref()
                    .is_some_and(|(ingress, entry)| !core.retains_fragment(*ingress, entry.info))
                {
                    cell.take();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::routing_input::{test_fragments, test_peer};
    use std::time::Duration;

    async fn core() -> (RoutedCore, Ingress) {
        let mut config = honk_config::Config::default();
        config.global.dial_mode = "ip".into();
        config.ensure_builtin_nodes();
        let plane = crate::control::tests::support::control_plane(config);
        let authority = plane
            .core_forward_policy(Execution::MixedEndpoints)
            .await
            .unwrap();
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let ingress = Ingress {
            scope: honk_datapath::ScopeId::allocate().unwrap(),
            namespace: socket_namespace(std::os::fd::AsFd::as_fd(&socket)).unwrap(),
            ifindex: 2,
            attachment: 1,
            mark: MarkProvenance::BeforeSkb,
        };
        let budget = MemoryBudget::new(32 << 20);
        let mut core =
            super::super::tests::unsynchronized_core(authority, &[ingress], &budget, None);
        core.prepare_fragment_peers().unwrap();
        (core, ingress)
    }

    #[tokio::test]
    async fn core_mixed_mac_completion_never_dispatches_and_poison_expires() {
        let (mut core, ingress) = core().await;
        let now = Instant::now();
        let fragments = test_fragments();
        for (index, mac) in [(0, [2; 6]), (1, [4; 6]), (2, [2; 6])] {
            assert!(
                core.receive_segments_with_peer_at(
                    ingress,
                    now,
                    now,
                    &[&fragments[index]],
                    Some(test_peer(1, 0, mac, 7))
                )
                .unwrap()
                .is_none()
            );
        }
        assert!(core.fragments_quiescent());
        assert!(
            core.fragment_peers
                .as_ref()
                .unwrap()
                .cells
                .iter()
                .all(Option::is_none)
        );
        for (index, mac) in [(1, [2; 6]), (2, [4; 6])] {
            assert!(
                core.receive_segments_with_peer_at(
                    ingress,
                    now,
                    now,
                    &[&fragments[index]],
                    Some(test_peer(1, 0, mac, 7))
                )
                .unwrap()
                .is_none()
            );
        }
        let retained = core.budget.used();
        core.core.retire(now + Duration::from_secs(31));
        core.reap_fragment_peers();
        assert!(core.fragments_quiescent());
        assert!(
            core.budget.used() < retained,
            "bounded reassembler reclaims poisoned bytes"
        );
        assert!(
            core.fragment_peers
                .as_ref()
                .unwrap()
                .cells
                .iter()
                .all(Option::is_none)
        );
    }

    #[tokio::test]
    async fn core_fragment_zero_selects_original_member_and_rejects_other_realms() {
        let (mut core, ingress) = core().await;
        let now = Instant::now();
        let fragments = test_fragments();
        for index in [1, 0] {
            let fragment = &fragments[index];
            let segments = [&fragment[..7], &fragment[7..]];
            assert!(
                core.receive_segments_with_peer_at(
                    ingress,
                    now,
                    now,
                    &segments,
                    Some(test_peer(1, index, [2; 6], 7))
                )
                .unwrap()
                .is_none()
            );
        }
        let (packet, peer) = core
            .receive_segments_with_peer_at(
                ingress,
                now,
                now,
                &[&fragments[2]],
                Some(test_peer(1, 2, [2; 6], 7)),
            )
            .unwrap()
            .unwrap();
        assert_eq!(peer.unwrap().original_path().device, 0);
        drop(packet);
        for (index, realm) in [(0, 1), (1, 2), (2, 1)] {
            assert!(
                core.receive_segments_with_peer_at(
                    ingress,
                    now,
                    now,
                    &[&fragments[index]],
                    Some(test_peer(realm, index, [2; 6], 7))
                )
                .unwrap()
                .is_none()
            );
        }
    }
}
