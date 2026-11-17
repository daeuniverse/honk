use super::*;
use honk_netstack::wire::{self, PacketView};

impl PacketEndpoints {
    pub(crate) fn realm(&self, scope: ScopeId) -> Option<&PacketRealm> {
        self.shared
            .realms
            .iter()
            .find(|realm| realm.scope() == scope)
    }

    pub(crate) fn execution_owner(
        &self,
        scope: ScopeId,
        view: PacketView<'_>,
    ) -> io::Result<&PacketScope> {
        let realm = self
            .realm(scope)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unowned packet realm"))?;
        Ok(&realm.owners()[realm.worker_for_packet(view)])
    }

    fn check_owner(&self, owner: &PacketScope) -> io::Result<()> {
        if self
            .realm(owner.scope())
            .is_some_and(|realm| realm.owners().iter().any(|scope| scope.same_owner(owner)))
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unowned packet execution owner",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn reassemble_for_dispatch_on(
        &self,
        owner: &PacketScope,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        peer: Option<crate::xdp::worker::PeerHold>,
    ) -> Result<
        Option<(
            honk_netstack::OwnedPacket,
            Option<crate::xdp::worker::PeerHold>,
        )>,
        honk_netstack::DropReason,
    > {
        self.check_owner(owner)
            .map_err(|_| honk_netstack::DropReason::NotForUs)?;
        owner.reassemble_for_dispatch_with_peer(packet, ingress_at, service_at, peer)
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive_on_timed(
        &self,
        owner: &PacketScope,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        mut admission: Option<EndpointAdmission>,
        check_output: bool,
        on_source: impl FnMut(ValidatedSource, bool) -> Option<crate::xdp::worker::PeerHold>,
    ) -> io::Result<PacketReceive> {
        self.check_owner(owner)?;
        if owner.is_host() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical receive cannot use a Host owner",
            ));
        }
        self.shared.udp_pool.reap_tasks();
        let receive = |admission: &mut Option<EndpointAdmission>| {
            owner.receive_realm_timed(
                packet,
                ingress_at,
                service_at,
                admission,
                check_output,
                on_source,
            )
        };
        let (rx, received, peer) =
            if wire::parse_ip(packet).is_ok_and(|ip| ip.proto == wire::PROTO_TCP) {
                EndpointAdmission::commit_pending(&mut admission, owner.scope(), receive)?
            } else {
                receive(&mut admission)
            };
        let physical = if matches!(
            &rx,
            Rx::Transparent { .. } | Rx::TransparentOwned { .. } | Rx::TransparentSplit { .. }
        ) {
            match peer.as_ref().filter(|peer| peer.learned()) {
                Some(peer) => Some(owner.hold_source(peer.address())?.with_peer(peer.clone())),
                None => None,
            }
        } else {
            None
        };
        owner.after_receive();
        self.dispatch_received::<true>(
            owner,
            packet,
            rx,
            received,
            None,
            admission,
            None,
            physical.as_ref(),
        )
    }
}

impl PacketRealm {
    pub(crate) fn worker_for_packet(&self, view: PacketView<'_>) -> usize {
        if self.owners().len() == 1 {
            return 0;
        }
        let Ok(ip) = view.parse_ip() else {
            return 0;
        };
        match ip.proto {
            wire::PROTO_UDP => self.worker_for_udp(ip.src),
            wire::PROTO_TCP => {
                let mut ports = [0; 4];
                if ip.payload.len() < ports.len()
                    || view
                        .copy_to(ip.payload.start..ip.payload.start + 4, &mut ports)
                        .is_none()
                {
                    return 0;
                }
                self.worker_for_tcp(
                    SocketAddr::new(ip.src, u16::from_be_bytes([ports[0], ports[1]])),
                    SocketAddr::new(ip.dst, u16::from_be_bytes([ports[2], ports[3]])),
                )
            }
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 => {
                if view.transport_ports(&ip).is_err() || ip.payload.len() < 8 {
                    return 0;
                }
                let mut kind = [0; 2];
                if view
                    .copy_to(ip.payload.start..ip.payload.start + 2, &mut kind)
                    .is_none()
                    || !matches!((ip.src.is_ipv4(), kind[0]), (true, 3) | (false, 1 | 2))
                {
                    return 0;
                }
                let mut quote = [0; 40 + 8 * 2048 + 8];
                let count = (ip.payload.len() - 8).min(quote.len());
                if view
                    .copy_to(
                        ip.payload.start + 8..ip.payload.start + 8 + count,
                        &mut quote[..count],
                    )
                    .is_none()
                {
                    return 0;
                }
                let Some(quote) = wire::icmp::parse_quoted(&quote[..count]) else {
                    return 0;
                };
                if quote.proto != wire::PROTO_TCP
                    || quote.seq.is_none()
                    || quote.src.is_ipv4() != ip.src.is_ipv4()
                {
                    return 0;
                }
                self.worker_for_tcp(
                    SocketAddr::new(quote.dst, quote.dst_port),
                    SocketAddr::new(quote.src, quote.src_port),
                )
            }
            _ => 0,
        }
    }
}
