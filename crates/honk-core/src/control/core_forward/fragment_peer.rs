use super::*;
use crate::control::netstack::FragmentPeer;
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
                None => FragmentPeer::new(info, peer.take()),
            };
            entry.observe(info, ingress_at, peer.take());
            for cell in &mut peers.cells {
                if cell.as_ref().is_some_and(|(owned, retained)| {
                    !self.core.retains_fragment(*owned, retained.info)
                }) {
                    cell.take();
                }
            }
            if packet.is_some() {
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
