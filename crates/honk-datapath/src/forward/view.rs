use super::*;
use honk_netstack::wire::PacketView;

pub struct ValidatedView<'a> {
    view: PacketView<'a>,
    ip: IpPacket,
    query: RouteQuery,
    deadline: Instant,
}
impl ValidatedView<'_> {
    pub fn query(&self) -> RouteQuery {
        self.query
    }
    pub fn ip(&self) -> &IpPacket {
        &self.ip
    }
    pub fn validate_core(&self) -> Result<(), ForwardError> {
        validate_execution(self.view, &self.ip)
    }
    pub fn permits_new_endpoint(&self) -> bool {
        permits_new_endpoint(self.view, &self.ip)
    }
}

/// A cached transit cursor borrowing RX storage only until its bytes reach reserved TX.
pub struct ForwardView<'a> {
    input: ValidatedView<'a>,
    flow: Arc<Flow>,
    route: Route,
    offset: usize,
    native: Option<crate::firewall::NativeLease>,
}
impl ForwardView<'_> {
    pub fn route(&self) -> Route {
        self.route
    }
    pub fn native_identity(&self) -> Option<(crate::firewall::Tuple, u16)> {
        native_identity(self.input.view, &self.input.ip, self.input.query)
    }
    pub fn bind_native(&mut self, native: crate::firewall::NativeLease) {
        self.native = Some(native);
    }
    pub fn next_len(&self) -> Option<usize> {
        shape(&self.input.ip, None, self.route, self.offset)
            .map(|(header, payload)| header + payload)
    }
    pub fn is_complete(&self) -> bool {
        self.offset == self.input.ip.payload.end
    }
    pub fn lease(&self) -> ForwardLease {
        ForwardLease {
            packet: None,
            flow: Arc::clone(&self.flow),
            _native: self.native.clone(),
        }
    }
    pub fn write_next_segments(&mut self, out: &mut [&mut [u8]], prefix: &[u8]) -> Option<usize> {
        write_next(
            self.input.view,
            &self.input.ip,
            None,
            self.route,
            self.native
                .as_ref()
                .map(crate::firewall::NativeLease::output_id),
            &mut self.offset,
            out,
            prefix,
        )
    }
}

impl CoreForward {
    pub fn ingress(&self, ifindex: u32) -> Option<Ingress> {
        self.inputs
            .iter()
            .find(|input| input.identity.ifindex == ifindex)
            .map(|input| input.identity)
    }

    pub fn ingresses(&self) -> impl ExactSizeIterator<Item = Ingress> + '_ {
        self.inputs.iter().map(|input| input.identity)
    }

    pub fn validate_view<'a>(
        &self,
        ingress: Ingress,
        now: Instant,
        view: PacketView<'a>,
    ) -> Result<ValidatedView<'a>, ForwardError> {
        if !self.inputs.iter().any(|input| input.identity == ingress) {
            return Err(ForwardError::Provenance);
        }
        let (ip, query) = inspect_view(ingress, view)?;
        Ok(ValidatedView {
            view,
            ip,
            query,
            deadline: now + Duration::from_secs(2),
        })
    }

    /// Cold route/fragment ownership may retain one funded contiguous copy. The cached
    /// path uses validate_view/prepare_view and never calls this materialization method.
    pub fn receive_segments(
        &mut self,
        ingress: Ingress,
        now: Instant,
        segments: &[&[u8]],
    ) -> Result<Option<Packet>, ForwardError> {
        let view = PacketView::new(segments)?;
        if view.len() > 65575 {
            return Err(ParseError::Malformed.into());
        }
        if matches!(view.parse_ip(), Err(ParseError::Fragment)) {
            let _charge = self
                .budget
                .reserve(view.len())
                .ok_or(ForwardError::Capacity)?;
            let mut bytes = vec![0; view.len()].into_boxed_slice();
            view.copy_to(0..view.len(), &mut bytes)
                .ok_or(ParseError::Malformed)?;
            return self.receive(ingress, now, &bytes);
        }
        let input = self.validate_view(ingress, now, view)?;
        let metadata = self
            .budget
            .reserve(size_of::<Packet>() + 32)
            .ok_or(ForwardError::Capacity)?;
        let charge = self
            .budget
            .reserve(input.ip.payload.end)
            .ok_or(ForwardError::Capacity)?;
        let mut bytes = vec![0; input.ip.payload.end].into_boxed_slice();
        view.copy_to(0..bytes.len(), &mut bytes)
            .ok_or(ParseError::Malformed)?;
        Ok(Some(Packet {
            bytes: Bytes::Copied(bytes, charge),
            ip: input.ip,
            query: input.query,
            input_query: input.query,
            deadline: input.deadline,
            validated: true,
            _metadata: metadata,
            binding: None,
            native: None,
            native_quote: None,
        }))
    }

    /// None requests the cold ICMP path. No packet bytes or flow claims are consumed then.
    pub fn prepare_view<'a>(
        &mut self,
        input: ValidatedView<'a>,
        route: Route,
        generation: u64,
        now: Instant,
    ) -> Result<Option<ForwardView<'a>>, ForwardError> {
        if check_route(
            self,
            &input.ip,
            input.query,
            input.view,
            None,
            route,
            (input.deadline, now),
        )?
        .is_some()
        {
            return Ok(None);
        }
        let flow = self.claim(input.query, route.ifindex, true, generation, now)?;
        Ok(Some(ForwardView {
            input,
            flow,
            route,
            offset: 0,
            native: None,
        }))
    }
}

pub(super) fn native_identity(
    view: PacketView<'_>,
    ip: &IpPacket,
    query: RouteQuery,
) -> Option<(crate::firewall::Tuple, u16)> {
    if !ip.src.is_ipv4() {
        return None;
    }
    let mut fields = [0; 4];
    view.copy_to(4..8, &mut fields)?;
    if fields[2] & 0x40 != 0 {
        return None;
    }
    let (source_port, destination_port) = if ip.proto == wire::PROTO_ICMP {
        let mut header = [0; 6];
        view.copy_to(
            ip.payload.start..ip.payload.start + header.len(),
            &mut header,
        )?;
        if matches!(header[0], 0 | 8) {
            let identifier = u16::from_be_bytes([header[4], header[5]]);
            (identifier, identifier)
        } else {
            (0, 0)
        }
    } else {
        query.ports.unwrap_or((0, 0))
    };
    Some((
        crate::firewall::Tuple {
            source: query.source,
            destination: query.destination,
            protocol: query.protocol,
            source_port,
            destination_port,
        },
        u16::from_be_bytes([fields[0], fields[1]]),
    ))
}

pub(super) fn inspect_view(
    ingress: Ingress,
    view: PacketView<'_>,
) -> Result<(IpPacket, RouteQuery), ForwardError> {
    if view.len() > 65575 {
        return Err(ParseError::Malformed.into());
    }
    let ip = view.parse_ip()?;
    if !unicast(ip.src) || !unicast(ip.dst) {
        return Err(ParseError::Unsupported.into());
    }
    let mut prefix = [0; 2];
    view.copy_to(0..2, &mut prefix)
        .ok_or(ParseError::Malformed)?;
    let ports = view.transport_ports(&ip)?;
    let traffic_class = if ip.src.is_ipv4() {
        prefix[1]
    } else {
        (prefix[0] & 15) << 4 | prefix[1] >> 4
    };
    let query = RouteQuery {
        ingress,
        source: ip.src,
        destination: ip.dst,
        traffic_class,
        protocol: ip.proto,
        ports,
    };
    Ok((ip, query))
}

pub(super) fn validate_execution(view: PacketView<'_>, ip: &IpPacket) -> Result<(), ForwardError> {
    if [ip.src, ip.dst]
        .iter()
        .any(|ip| matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local()))
    {
        return Err(ParseError::Unsupported.into());
    }
    let mut prefix = [0; 60];
    let count = view.len().min(prefix.len());
    view.copy_to(0..count, &mut prefix[..count])
        .ok_or(ParseError::Malformed)?;
    validate_options(&prefix[..count], ip)?;
    Ok(())
}

pub(super) fn check_route(
    core: &CoreForward,
    ip: &IpPacket,
    query: RouteQuery,
    view: PacketView<'_>,
    ipv6_fragment: Option<Ipv6Fragment>,
    route: Route,
    (deadline, now): (Instant, Instant),
) -> Result<Option<TransitError>, ForwardError> {
    validate_execution(view, ip)?;
    if !core
        .inputs
        .iter()
        .any(|input| input.identity == query.ingress)
        || route.generation == 0
        || route.ifindex == 0
        || !route.l2.valid()
        || route.next_hop.is_ipv4() != ip.src.is_ipv4()
        || [route.source_mac, route.destination_mac]
            .iter()
            .any(|mac| *mac == [0; 6] || mac[0] & 1 != 0)
    {
        return Err(ForwardError::Provenance);
    }
    if now >= deadline {
        return Err(ForwardError::Expired);
    }
    forwarding_error(view, ip, ipv6_fragment, route.mtu)
}

pub(super) fn permits_new_endpoint(view: PacketView<'_>, ip: &IpPacket) -> bool {
    match ip.proto {
        wire::PROTO_UDP => true,
        wire::PROTO_TCP => {
            let mut flags = [0];
            view.copy_to(ip.payload.start + 13..ip.payload.start + 14, &mut flags)
                .is_some()
                && flags[0] & (wire::tcp::SYN | wire::tcp::ACK | wire::tcp::FIN | wire::tcp::RST)
                    == wire::tcp::SYN
        }
        _ => false,
    }
}

pub(super) fn forwarding_error(
    view: PacketView<'_>,
    ip: &IpPacket,
    ipv6_fragment: Option<Ipv6Fragment>,
    mtu: u32,
) -> Result<Option<TransitError>, ForwardError> {
    if ip.hop_limit <= 1 {
        return Ok(Some(TransitError::HopLimitExceeded));
    }
    if mtu < if ip.src.is_ipv6() { 1280 } else { 68 } {
        return Err(ForwardError::Provenance);
    }
    let mut flags = [0];
    view.copy_to(6..7, &mut flags)
        .ok_or(ParseError::Malformed)?;
    let too_big = if ip.src.is_ipv6() {
        ipv6_fragment.map_or(ip.payload.end, |fragment| fragment.max_size) > mtu as usize
    } else {
        ip.payload.end > mtu as usize && flags[0] & 0x40 != 0
    };
    if too_big {
        return Ok(Some(TransitError::PacketTooBig { mtu }));
    }
    Ok(None)
}

pub(super) fn shape(
    ip: &IpPacket,
    ipv6_fragment: Option<Ipv6Fragment>,
    route: Route,
    offset: usize,
) -> Option<(usize, usize)> {
    if offset == ip.payload.end {
        return None;
    }
    if let Some(fragment) = ipv6_fragment {
        // Linux ip6_fragment checks the received maximum against egress before this floor.
        let mtu = (route.mtu as usize).min(fragment.max_size.max(1280));
        let available = mtu.checked_sub(48)?;
        let remaining = ip.payload.len().checked_sub(offset)?;
        let payload = if remaining > available {
            available / 8 * 8
        } else {
            remaining
        };
        return (payload != 0).then_some((48, payload));
    }
    if ip.payload.end <= route.mtu as usize {
        return Some((ip.payload.start, ip.payload.len()));
    }
    if ip.src.is_ipv6() {
        return None;
    }
    let header = if offset == 0 { ip.payload.start } else { 20 };
    let available = (route.mtu as usize).checked_sub(header)?;
    let remaining = ip.payload.len().checked_sub(offset)?;
    let payload = if remaining > available {
        available / 8 * 8
    } else {
        remaining
    };
    (payload != 0).then_some((header, payload))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_next(
    view: PacketView<'_>,
    ip: &IpPacket,
    ipv6_fragment: Option<Ipv6Fragment>,
    route: Route,
    output_id: Option<u16>,
    offset: &mut usize,
    out: &mut [&mut [u8]],
    prefix: &[u8],
) -> Option<usize> {
    let (header_len, payload) = shape(ip, ipv6_fragment, route, *offset)?;
    let length = header_len + payload;
    let total = prefix.len().checked_add(length)?;
    let capacity = out
        .iter()
        .try_fold(0usize, |size, part| size.checked_add(part.len()))?;
    if capacity < total {
        return None;
    }
    let copy_len = if ipv6_fragment.is_some() {
        40
    } else {
        header_len
    };
    let mut header = [0; 60];
    view.copy_to(0..copy_len, &mut header[..copy_len])?;
    let fragmented = ipv6_fragment.is_some() || ip.payload.end > route.mtu as usize;
    let more = fragmented && *offset + payload < ip.payload.len();
    if ip.src.is_ipv4() {
        header[0] = 0x40 | (header_len / 4) as u8;
        if let Some(id) = output_id {
            header[4..6].copy_from_slice(&id.to_be_bytes());
        }
        if fragmented {
            header[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            let field = (*offset / 8) as u16 | if more { 0x2000 } else { 0 };
            header[6..8].copy_from_slice(&field.to_be_bytes());
        }
        header[8] = ip.hop_limit - 1;
        header[10..12].fill(0);
        let checksum = wire::checksum::checksum(&header[..header_len]);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
    } else {
        header[7] = ip.hop_limit - 1;
        if let Some(fragment) = ipv6_fragment {
            header[4..6].copy_from_slice(&((payload + 8) as u16).to_be_bytes());
            header[6] = 44;
            header[40] = ip.proto;
            let field = *offset as u16 | u16::from(more);
            header[42..44].copy_from_slice(&field.to_be_bytes());
            header[44..48].copy_from_slice(&fragment.id.to_be_bytes());
        }
    }
    write_at(out, 0, prefix)?;
    write_at(out, prefix.len(), &header[..header_len])?;
    let mut at = prefix.len() + header_len;
    view.visit(
        ip.payload.start + *offset..ip.payload.start + *offset + payload,
        |bytes| {
            // Capacity and ranges were checked before any cursor mutation.
            write_at(out, at, bytes).expect("reserved output capacity");
            at += bytes.len();
        },
    )?;
    *offset = if more {
        *offset + payload
    } else {
        ip.payload.end
    };
    Some(total)
}

fn write_at(out: &mut [&mut [u8]], mut offset: usize, mut bytes: &[u8]) -> Option<()> {
    for part in out {
        if offset >= part.len() {
            offset -= part.len();
            continue;
        }
        let count = bytes.len().min(part.len() - offset);
        part[offset..offset + count].copy_from_slice(&bytes[..count]);
        bytes = &bytes[count..];
        offset = 0;
        if bytes.is_empty() {
            return Some(());
        }
    }
    bytes.is_empty().then_some(())
}
