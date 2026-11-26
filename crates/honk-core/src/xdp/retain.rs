use super::*;

// Boxing retained owners would allocate on the packet output path.
#[allow(clippy::large_enum_variant)]
pub(super) enum Retained {
    Endpoint(OutputOwner),
    Forward {
        _owner: ForwardLease,
        _peer: Option<worker::PeerHold>,
    },
    Error {
        _binding: Option<honk_datapath::firewall::BindingLease>,
        _peer: Option<worker::PeerHold>,
    },
    Generated {
        _owner: GeneratedError,
    },
}

pub(super) fn release_completed(completed: &mut [Option<&mut Retained>]) {
    let mut outputs: [Option<&mut OutputOwner>; 64] = std::array::from_fn(|_| None);
    let mut count = 0;
    for owner in completed.iter_mut().filter_map(Option::take) {
        if let Retained::Endpoint(output) = owner {
            outputs[count] = Some(output);
            count += 1;
        }
    }
    OutputOwner::release_batch(&mut outputs[..count]);
}

impl ReturnPath {
    pub(crate) fn same_identity(self, other: Self) -> bool {
        self.realm == other.realm
            && self.mac == other.mac
            && self.vlan_proto == other.vlan_proto
            && self.vlan_count == other.vlan_count
            && self
                .vlan_tci
                .iter()
                .zip(other.vlan_tci)
                .all(|(old, new)| old & 0x0fff == new & 0x0fff)
    }
}

pub(super) fn retained_endpoint(
    endpoints: &PacketEndpoints,
    scope: ScopeId,
    view: PacketView<'_>,
) -> bool {
    let Ok(ip) = view.parse_ip() else {
        return false;
    };
    if matches!(ip.proto, wire::PROTO_ICMP | wire::PROTO_ICMPV6) {
        return retained_icmp(endpoints, scope, view, &ip);
    }
    if !matches!(ip.proto, 6 | 17) || ip.payload.len() < 4 {
        return false;
    }
    let mut ports = [0; 4];
    if view
        .copy_to(ip.payload.start..ip.payload.start + 4, &mut ports)
        .is_none()
    {
        return false;
    }
    endpoints.retained_transport(
        scope,
        std::net::SocketAddr::new(ip.src, u16::from_be_bytes([ports[0], ports[1]])),
        std::net::SocketAddr::new(ip.dst, u16::from_be_bytes([ports[2], ports[3]])),
        ip.proto,
    )
}

#[inline(never)]
fn retained_icmp(
    endpoints: &PacketEndpoints,
    scope: ScopeId,
    view: PacketView<'_>,
    ip: &wire::IpPacket,
) -> bool {
    if view.transport_ports(ip).is_err() || ip.payload.len() < 8 {
        return false;
    }
    let mut kind = [0; 2];
    if view
        .copy_to(ip.payload.start..ip.payload.start + 2, &mut kind)
        .is_none()
    {
        return false;
    }
    if !matches!((ip.src.is_ipv4(), kind[0]), (true, 3) | (false, 1 | 2)) {
        return false;
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
        return false;
    }
    let Some(quote) = wire::icmp::parse_quoted(&quote[..count]) else {
        return false;
    };
    quote.proto == wire::PROTO_TCP
        && quote.seq.is_some()
        && quote.src.is_ipv4() == ip.src.is_ipv4()
        && endpoints.retains(
            scope,
            std::net::SocketAddr::new(quote.dst, quote.dst_port),
            std::net::SocketAddr::new(quote.src, quote.src_port),
            quote.proto,
        )
}

#[cfg(test)]
fn peer_policy(
    peers: &[Peer],
    endpoints: &PacketEndpoints,
    scope: ScopeId,
    address: IpAddr,
    path: ReturnPath,
    now: Instant,
) -> PeerPolicy {
    if let Some(peer) = peers
        .iter()
        .find(|peer| peer.scope == scope && peer.address == address)
    {
        if peer.path == path && peer.conflict.is_none() {
            return PeerPolicy::default();
        }
        return PeerPolicy {
            retained: endpoints.retains_source(scope, address),
            output: peer.path != path,
            evict: None,
        };
    }
    PeerPolicy {
        // ponytail: reclamation scans only at the fixed 4096-peer ceiling; index if measured.
        evict: (peers.len() == PEERS)
            .then(|| {
                peers
                    .iter()
                    .enumerate()
                    .filter(|(_, peer)| {
                        peer.conflict.is_none_or(|last| {
                            now.saturating_duration_since(last) >= PEER_CONFLICT_HOLD
                        }) && !endpoints.retains_source(peer.scope, peer.address)
                    })
                    .min_by_key(|(_, peer)| peer.last_seen)
                    .map(|(index, _)| index)
            })
            .flatten(),
        ..Default::default()
    }
}

#[cfg(test)]
fn remember_peer(
    peers: &mut Vec<Peer>,
    scope: ScopeId,
    source: honk_netstack::ValidatedSource,
    path: ReturnPath,
    now: Instant,
    policy: PeerPolicy,
    pressure: &mut PressureCounters,
) -> bool {
    let address = source.src.ip();
    if address.is_unspecified() || address.is_multicast() || path.mac[0] & 1 != 0 {
        return false;
    }
    if source
        .tcp_flags
        .is_some_and(|flags| flags & wire::tcp::RST != 0)
    {
        return peers
            .iter()
            .find(|peer| peer.scope == scope && peer.address == address)
            .is_none_or(|peer| peer.path.same_identity(path) && peer.conflict.is_none());
    }
    let opens = source.protocol == wire::PROTO_UDP
        || source.tcp_flags.is_some_and(|flags| {
            flags & (wire::tcp::SYN | wire::tcp::ACK | wire::tcp::RST | wire::tcp::FIN)
                == wire::tcp::SYN
        });
    if let Some(peer) = peers
        .iter_mut()
        .find(|peer| peer.scope == scope && peer.address == address)
    {
        if !peer.path.same_identity(path) || peer.conflict.is_some() {
            if !opens || policy.retained {
                pressure.peer_conflict = pressure.peer_conflict.saturating_add(1);
                pressure.refused = true;
                return false;
            }
            if !peer
                .conflict
                .is_some_and(|last| now.saturating_duration_since(last) >= PEER_CONFLICT_HOLD)
            {
                peer.conflict = Some(now);
                pressure.peer_conflict = pressure.peer_conflict.saturating_add(1);
                pressure.refused = true;
                return false;
            }
            peer.conflict = None;
        }
        if !policy.output {
            peer.path = path;
        }
        if source
            .tcp_flags
            .is_none_or(|flags| flags & wire::tcp::RST == 0)
        {
            peer.last_seen = now;
        }
        return true;
    }
    if !opens {
        return true;
    }
    let peer = Peer {
        scope,
        address,
        path,
        last_seen: now,
        conflict: None,
    };
    if peers.len() == PEERS {
        let Some(index) = policy.evict else {
            pressure.peer_full = pressure.peer_full.saturating_add(1);
            pressure.refused = true;
            return false;
        };
        peers[index] = peer;
        pressure.peer_reclaimed = pressure.peer_reclaimed.saturating_add(1);
    } else {
        peers.push(peer);
    }
    true
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn receive_endpoint(
    endpoints: &PacketEndpoints,
    peers: &mut Vec<Peer>,
    pressure: &mut PressureCounters,
    scope: ScopeId,
    packet: &[u8],
    now: Instant,
    path: ReturnPath,
    admission: Option<EndpointAdmission>,
) -> io::Result<PacketReceive> {
    let policy = match wire::parse_ip(packet) {
        Ok(ip)
            if ip.proto == wire::PROTO_TCP
                && packet[ip.payload.clone()]
                    .get(13)
                    .is_some_and(|flags| flags & wire::tcp::RST != 0) =>
        {
            PeerPolicy::default()
        }
        Ok(ip) if matches!(ip.proto, wire::PROTO_TCP | wire::PROTO_UDP) => {
            peer_policy(peers, endpoints, scope, ip.src, path, now)
        }
        Err(wire::ParseError::Fragment) => wire::packet_addresses(packet)
            .map(|(source, _)| peer_policy(peers, endpoints, scope, source, path, now))
            .unwrap_or_default(),
        _ => PeerPolicy::default(),
    };
    let check_output = policy.output;
    let mut policy = Some(policy);
    let on_source = |source, pending| {
        let mut policy = policy.take().expect("one completed source");
        policy.output = pending;
        remember_peer(peers, scope, source, path, now, policy, pressure)
    };
    let result = match admission {
        Some(admission) => endpoints.receive_admitted_with_source(
            scope,
            packet,
            now,
            admission,
            check_output,
            on_source,
        ),
        None => endpoints.receive_with_source(scope, packet, now, check_output, on_source),
    };
    if result.as_ref().is_err_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory
        )
    }) {
        pressure.endpoint_capacity = pressure.endpoint_capacity.saturating_add(1);
        pressure.refused = true;
    }
    result
}

#[cfg(test)]
pub(super) fn endpoint_return_path(peers: &[Peer], output: &OutputLease) -> Option<ReturnPath> {
    let (_, destination) = wire::packet_addresses(output.packet()).ok()?;
    peer_return_path(peers, output.scope(), destination)
}

#[cfg(test)]
pub(super) fn peer_return_path(
    peers: &[Peer],
    scope: ScopeId,
    destination: IpAddr,
) -> Option<ReturnPath> {
    peers
        .iter()
        .find(|peer| peer.scope == scope && peer.address == destination && peer.conflict.is_none())
        .map(|peer| peer.path)
}

pub(super) fn return_header(
    path: ReturnPath,
    source: [u8; 6],
    physical_ifindex: u32,
    ipv6: bool,
) -> io::Result<honk_datapath::forward::EthernetHeader> {
    LinkPath {
        physical_ifindex,
        vlan_tci: path.vlan_tci,
        vlan_proto: path.vlan_proto,
        vlan_count: path.vlan_count,
    }
    .header(source, path.mac, ipv6)
    .map_err(io::Error::other)
}
