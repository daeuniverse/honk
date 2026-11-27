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
    ) -> io::Result<(&PacketScope, Option<TcpClaim>)> {
        let realm = self
            .realm(scope)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unowned packet realm"))?;
        realm.dispatch_owner(0, view)
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
    fn auxiliary_driver_scope(&self, driver: &PacketDriver) -> io::Result<ScopeId> {
        let owner = driver.owner_scope();
        if !owner.is_auxiliary() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "auxiliary driver required",
            ));
        }
        self.check_owner(owner)?;
        Ok(owner.scope())
    }

    #[cfg(target_os = "linux")]
    /// Retire one binding while continuing to drive its original scope.
    pub(crate) async fn pause_auxiliary(&self, driver: &mut PacketDriver) -> io::Result<()> {
        let scope = self.auxiliary_driver_scope(driver)?;
        driver.begin_auxiliary_pause()?;
        self.shared.udp_pool.retire_auxiliary_scope(scope);
        driver.drain_auxiliary().await
    }

    #[cfg(target_os = "linux")]
    /// Open a fresh binding after scoped work and its output have drained.
    pub(crate) fn resume_auxiliary(&self, driver: &mut PacketDriver, mtu: u32) -> io::Result<()> {
        let scope = self.auxiliary_driver_scope(driver)?;
        driver.resume_auxiliary(mtu, || {
            // Old initializers have returned and the next binding cannot admit packets yet.
            self.shared.sniffer_pool.clear_scope(scope);
            self.shared.auxiliary_admission_open()
        })
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
        if owner.is_auxiliary() {
            return Err(honk_netstack::DropReason::NotForUs);
        }
        owner.reassemble_for_dispatch_with_peer(packet, ingress_at, service_at, peer)
    }

    /// Receives an L3 TUN packet on the owner already selected by the device worker.
    #[cfg(target_os = "linux")]
    pub(crate) fn receive_tun_on(
        &self,
        owner: &PacketScope,
        packet: &[u8],
        meta: RxMeta,
        ingress_at: Instant,
        service_at: Instant,
        mut on_source: impl FnMut(ValidatedSource, bool) -> bool,
    ) -> io::Result<PacketReceive> {
        self.check_owner(owner)?;
        self.receive_selected::<true>(
            owner,
            (packet, meta),
            ingress_at,
            service_at,
            None,
            None,
            false,
            |source, _, _, pending| on_source(source, pending),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn can_batch_tcp(&self) -> bool {
        !self.is_closing() && !self.shared.udp_pool.has_completed_tasks()
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
        if owner.is_host() || owner.is_auxiliary() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical receive requires a physical owner",
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
        let (rx, received, physical) = if admission.is_some()
            && wire::parse_ip(packet).is_ok_and(|ip| ip.proto == wire::PROTO_TCP)
        {
            EndpointAdmission::commit_pending(&mut admission, owner.scope(), receive)?
        } else {
            receive(&mut admission)
        }?;
        owner.after_receive();
        match self.dispatch_received::<true>(
            owner,
            packet,
            rx,
            received,
            None,
            admission,
            None,
            physical.as_ref(),
            None,
        ) {
            Err(error)
                if error
                    .get_ref()
                    .is_some_and(|cause| cause.is::<DatagramAdmissionClosed>()) =>
            {
                Ok(received)
            }
            result => result,
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive_local_on_timed(
        &self,
        driver: &mut PacketDriver,
        packet: &[u8],
        ingress_at: Instant,
        service_at: Instant,
        mut admission: Option<EndpointAdmission>,
        check_output: bool,
        on_source: impl FnMut(ValidatedSource, bool) -> Option<crate::xdp::worker::PeerHold>,
    ) -> io::Result<PacketReceive> {
        let owner = driver.owner_scope();
        self.check_owner(owner)?;
        if owner.is_host() || owner.is_auxiliary() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical receive requires a physical owner",
            ));
        }
        let scope = owner.scope();
        self.shared.udp_pool.reap_tasks();
        let receive = |admission: &mut Option<EndpointAdmission>| {
            driver.receive_realm_timed(
                packet,
                ingress_at,
                service_at,
                admission,
                check_output,
                on_source,
            )
        };
        let (rx, received, physical) = if admission.is_some()
            && wire::parse_ip(packet).is_ok_and(|ip| ip.proto == wire::PROTO_TCP)
        {
            EndpointAdmission::commit_pending(&mut admission, scope, receive)?
        } else {
            receive(&mut admission)
        }?;
        let result = self.dispatch_received::<true>(
            driver.owner_scope(),
            packet,
            rx,
            received,
            None,
            admission,
            None,
            physical.as_ref(),
            None,
        );
        self.accept_local_ready(driver)?;
        match result {
            Err(error)
                if error
                    .get_ref()
                    .is_some_and(|cause| cause.is::<DatagramAdmissionClosed>()) =>
            {
                Ok(received)
            }
            result => result,
        }
    }
}

impl PacketRealm {
    pub(crate) fn dispatch_owner(
        &self,
        local: usize,
        view: PacketView<'_>,
    ) -> io::Result<(&PacketScope, Option<TcpClaim>)> {
        if self.owners().len() == 1 {
            return Ok((&self.owners()[0], None));
        }
        let Ok(ip) = view.parse_ip() else {
            return Ok((&self.owners()[0], None));
        };
        let (worker, claim) = match ip.proto {
            wire::PROTO_UDP => {
                let mut port = [0; 2];
                if ip.payload.len() < 8
                    || view
                        .copy_to(ip.payload.start..ip.payload.start + 2, &mut port)
                        .is_none()
                {
                    return Ok((&self.owners()[0], None));
                }
                let client = SocketAddr::new(ip.src, u16::from_be_bytes(port));
                (self.worker_for_udp(client), None)
            }
            wire::PROTO_TCP => {
                let mut header = [0; 14];
                let needed = if self.queue_affine() { header.len() } else { 4 };
                if ip.payload.len() < needed
                    || view
                        .copy_to(
                            ip.payload.start..ip.payload.start + needed,
                            &mut header[..needed],
                        )
                        .is_none()
                {
                    return Ok((&self.owners()[0], None));
                }
                self.tcp_dispatch(
                    local,
                    SocketAddr::new(ip.src, u16::from_be_bytes([header[0], header[1]])),
                    SocketAddr::new(ip.dst, u16::from_be_bytes([header[2], header[3]])),
                    header[13]
                        & (wire::tcp::SYN | wire::tcp::FIN | wire::tcp::RST | wire::tcp::ACK)
                        == wire::tcp::SYN,
                )?
            }
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 => (self.quoted_worker(view, &ip), None),
            _ => (0, None),
        };
        Ok((&self.owners()[worker], claim))
    }

    fn quoted_worker(&self, view: PacketView<'_>, ip: &wire::IpPacket) -> usize {
        if view.transport_ports(ip).is_err() || ip.payload.len() < 8 {
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
        let source = SocketAddr::new(quote.dst, quote.dst_port);
        let destination = SocketAddr::new(quote.src, quote.src_port);
        if self.queue_affine() {
            self.retained_affine_worker(source, destination)
                .unwrap_or(0)
        } else {
            self.worker_for_tcp(source, destination)
        }
    }
}
