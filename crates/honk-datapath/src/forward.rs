//! Routed packet processing. Policy and kernel FIB authority stay with the adapter.
//!
//! Never feed transit TCP to `Stack`: validated bytes retain the original transport.
//! A scope is an index, not proof of namespace, logical ingress, marks or capture ownership.

use crate::ScopeId;
use honk_netstack::{
    FragmentLimits, MemoryBudget, MemoryReservation, OwnedPacket,
    transit::{Ipv6Fragment, Transit, TransitError, unicast},
    wire::{self, IpPacket, ParseError},
};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
mod view;
pub use view::{ForwardView, ValidatedView};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MarkProvenance {
    /// Actual pre-routing skb mark, supplied by the capture authority.
    Captured(u32),
    /// Explicit XDP deployment: no pre-XDP skb classification is required.
    BeforeSkb,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ingress {
    pub scope: ScopeId,
    pub namespace: u64,
    pub ifindex: u32,
    pub attachment: u64,
    pub mark: MarkProvenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentObligation {
    pub ingress: Ingress,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
}
impl From<RouteQuery> for FragmentObligation {
    fn from(query: RouteQuery) -> Self {
        Self {
            ingress: query.ingress,
            source: query.source,
            destination: query.destination,
            protocol: query.protocol,
        }
    }
}

// RFC 5382 REQ-5 and RFC 4787 REQ-5 keep idle reverse traffic with its executor.
pub(crate) const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60 + 4 * 60);
pub(crate) const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouteQuery {
    pub ingress: Ingress,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub traffic_class: u8,
    pub protocol: u8,
    pub ports: Option<(u16, u16)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkPath {
    pub physical_ifindex: u32,
    pub vlan_proto: [u16; 2],
    pub vlan_tci: [u16; 2],
    pub vlan_count: u8,
}

impl LinkPath {
    pub const fn untagged(physical_ifindex: u32) -> Self {
        Self {
            physical_ifindex,
            vlan_proto: [0; 2],
            vlan_tci: [0; 2],
            vlan_count: 0,
        }
    }

    pub fn valid(self) -> bool {
        self.physical_ifindex != 0
            && self.vlan_count <= 2
            && (0..2).all(|index| {
                if index < usize::from(self.vlan_count) {
                    matches!(self.vlan_proto[index], 0x8100 | 0x88a8)
                        && self.vlan_tci[index] & 0x0fff != 0x0fff
                } else {
                    self.vlan_proto[index] == 0 && self.vlan_tci[index] == 0
                }
            })
    }

    pub fn header(
        self,
        source: [u8; 6],
        destination: [u8; 6],
        ipv6: bool,
    ) -> Result<EthernetHeader, ForwardError> {
        if !self.valid() {
            return Err(ForwardError::Provenance);
        }
        let mut bytes = [0; 22];
        bytes[..6].copy_from_slice(&destination);
        bytes[6..12].copy_from_slice(&source);
        let mut at = 12;
        for index in 0..usize::from(self.vlan_count) {
            bytes[at..at + 2].copy_from_slice(&self.vlan_proto[index].to_be_bytes());
            bytes[at + 2..at + 4].copy_from_slice(&self.vlan_tci[index].to_be_bytes());
            at += 4;
        }
        bytes[at..at + 2]
            .copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800u16 }).to_be_bytes());
        Ok(EthernetHeader { bytes, len: at + 2 })
    }
}

pub struct EthernetHeader {
    bytes: [u8; 22],
    len: usize,
}

impl std::ops::Deref for EthernetHeader {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// A parsed kernel result is not by itself an authorization: its provider generation must
/// still be current under the adapter's submission fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub generation: u64,
    pub ifindex: u32,
    pub l2: LinkPath,
    pub mtu: u32,
    pub next_hop: IpAddr,
    pub preferred_source: Option<IpAddr>,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
}

impl Route {
    pub fn ethernet_header(self, ipv6: bool) -> Result<EthernetHeader, ForwardError> {
        self.l2.header(self.source_mac, self.destination_mac, ipv6)
    }
}

#[derive(Debug)]
pub enum ForwardError {
    Packet(ParseError),
    Capacity,
    Provenance,
    Expired,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ForwardError {}
impl From<ParseError> for ForwardError {
    fn from(error: ParseError) -> Self {
        Self::Packet(error)
    }
}

enum Bytes {
    Copied(Box<[u8]>, MemoryReservation),
    Reassembled(OwnedPacket),
}
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Copied(bytes, charge) => {
                let _ = charge;
                bytes
            }
            Self::Reassembled(bytes) => bytes,
        }
    }
}
impl AsMut<[u8]> for Bytes {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Copied(bytes, _) => bytes,
            Self::Reassembled(bytes) => bytes.as_mut(),
        }
    }
}

pub struct Packet {
    bytes: Bytes,
    ip: IpPacket,
    query: RouteQuery,
    input_query: RouteQuery,
    deadline: Instant,
    validated: bool,
    binding: Option<crate::firewall::BindingLease>,
    native: Option<crate::firewall::NativeLease>,
    native_quote: Option<crate::firewall::NativeQuoteLease>,
    _metadata: MemoryReservation,
}
impl Packet {
    pub fn query(&self) -> RouteQuery {
        self.query
    }
    pub fn input_query(&self) -> RouteQuery {
        self.input_query
    }
    pub fn set_input_query(&mut self, query: RouteQuery) {
        self.input_query = query;
    }
    pub fn ip(&self) -> &IpPacket {
        &self.ip
    }
    pub fn is_reassembled(&self) -> bool {
        matches!(self.bytes, Bytes::Reassembled(_))
    }
    pub fn ipv6_fragment(&self) -> Option<Ipv6Fragment> {
        match &self.bytes {
            Bytes::Reassembled(packet) => packet.ipv6_fragment(),
            Bytes::Copied(..) => None,
        }
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn received_at(&self) -> Instant {
        self.deadline - Duration::from_secs(2)
    }
    pub fn is_validated(&self) -> bool {
        self.validated
    }
    pub fn validate_core(&self) -> Result<(), ForwardError> {
        view::validate_execution(wire::PacketView::from_slice(self.as_ref()), &self.ip)
    }
    pub fn permits_new_endpoint(&self) -> bool {
        view::permits_new_endpoint(wire::PacketView::from_slice(self.as_ref()), &self.ip)
    }

    /// Requires input-FIB authority, but not the forward neighbor's Ethernet address.
    pub fn forwarding_error(&self, mtu: u32) -> Result<Option<TransitError>, ForwardError> {
        view::forwarding_error(
            wire::PacketView::from_slice(self.as_ref()),
            &self.ip,
            self.ipv6_fragment(),
            mtu,
        )
    }
    /// Packet-local checks; policy and FIB generations still belong to the adapter fence.
    pub fn is_current(&self, now: Instant) -> bool {
        self.validated
            && now < self.deadline
            && self
                .binding
                .as_ref()
                .is_none_or(|binding| binding.is_active())
    }
    pub fn binding(&self) -> Option<&crate::firewall::BindingLease> {
        self.binding.as_ref()
    }
    /// After copying a generated error, only its NAT grant needs to follow device CQ.
    pub fn into_binding(self) -> Option<crate::firewall::BindingLease> {
        self.binding
    }
    pub fn bind(&mut self, binding: crate::firewall::BindingLease) {
        self.binding = Some(binding);
    }
    pub fn native_identity(&self) -> Option<(crate::firewall::Tuple, u16)> {
        view::native_identity(
            wire::PacketView::from_slice(self.as_ref()),
            &self.ip,
            self.query,
        )
    }
    pub fn bind_native(&mut self, native: crate::firewall::NativeLease) {
        self.native = Some(native);
    }
    pub fn retain_native_quote(&mut self, quote: crate::firewall::NativeQuoteLease) {
        self.native_quote = Some(quote);
    }
    pub fn native_quote(&self) -> Option<&crate::firewall::NativeQuoteLease> {
        self.native_quote.as_ref()
    }

    /// In-place translation retains the original byte reservation. A failed transform or
    /// validation permanently denies submission until a subsequent complete rewrite succeeds.
    pub fn rewrite(
        &mut self,
        transform: impl FnOnce(&mut [u8]) -> Result<(), ForwardError>,
    ) -> Result<(), ForwardError> {
        self.validated = false;
        transform(self.bytes.as_mut())?;
        let (ip, query) = inspect(self.query.ingress, self.bytes.as_ref())?;
        self.ip = ip;
        self.query = query;
        self.validated = true;
        Ok(())
    }
}
impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

struct Flow {
    query: RouteQuery,
    reply_ingress: Option<Ingress>,
    standalone: bool,
    generation: u64,
    _charge: MemoryReservation,
}
impl Flow {
    fn matches(&self, query: RouteQuery) -> bool {
        same_transport(&self.query, &query)
            || (self.reply_ingress == Some(query.ingress)
                && self.query.protocol == query.protocol
                && self.query.source == query.destination
                && self.query.destination == query.source
                && self.query.ports
                    == query
                        .ports
                        .map(|(source, destination)| (destination, source)))
    }
}
struct Entry {
    flow: Arc<Flow>,
    last: Instant,
}
impl Entry {
    fn retained(&self, now: Instant) -> bool {
        // Without TCP sequence/window authority, FIN/RST cannot prove retirement.
        let ttl = match self.flow.query.protocol {
            wire::PROTO_TCP => TCP_IDLE_TIMEOUT,
            wire::PROTO_UDP => UDP_IDLE_TIMEOUT,
            _ => Duration::from_secs(60),
        };
        now.saturating_duration_since(self.last) < ttl || Arc::strong_count(&self.flow) > 1
    }
}

struct Input {
    identity: Ingress,
    transit: Transit,
}

/// A slow owner stays in this directory until its idle horizon AND every output lease
/// have retired. There is no promotion to native forwarding, even after FIB changes.
pub struct CoreForward {
    inputs: Vec<Input>,
    budget: Arc<MemoryBudget>,
    flows: Vec<Entry>,
    max_flows: usize,
    _metadata: MemoryReservation,
}

// Keep the funded packet inline on this cold path; the borrowed hot path uses ForwardView.
#[allow(clippy::large_enum_variant)]
pub enum Prepared {
    Forward(ForwardPacket),
    Error { packet: Packet, error: TransitError },
}

/// Materialization cursor: all fragments retain the same original packet/flow owner.
/// Call `write_next` only after reserving device capacity; retain its returned lease to CQ.
pub struct ForwardPacket {
    packet: Arc<Packet>,
    flow: Arc<Flow>,
    route: Route,
    offset: usize,
}

pub struct ForwardLease {
    packet: Option<Arc<Packet>>,
    flow: Arc<Flow>,
    _native: Option<crate::firewall::NativeLease>,
}
impl ForwardLease {
    pub fn policy_generation(&self) -> u64 {
        self.flow.generation
    }
    pub fn ingress(&self) -> Ingress {
        self.flow.query.ingress
    }
    pub fn retained_packet(&self) -> Option<&Packet> {
        self.packet.as_deref()
    }
}

impl CoreForward {
    pub fn new(
        ingresses: &[Ingress],
        budget: Arc<MemoryBudget>,
        max_flows: usize,
    ) -> Result<Self, ForwardError> {
        let first = ingresses.first().ok_or(ForwardError::Provenance)?;
        if ingresses.len() > 64
            || ingresses.iter().enumerate().any(|(index, ingress)| {
                ingress.namespace == 0
                    || ingress.namespace != first.namespace
                    || ingress.scope != first.scope
                    || ingress.ifindex == 0
                    || ingress.attachment == 0
                    || matches!(ingress.mark, MarkProvenance::Unavailable)
                    || ingresses[..index]
                        .iter()
                        .any(|other| other.ifindex == ingress.ifindex)
            })
        {
            return Err(ForwardError::Provenance);
        }
        if max_flows == 0 || max_flows > 4096 {
            return Err(ForwardError::Capacity);
        }
        let metadata = budget
            .reserve(
                max_flows
                    .checked_mul(size_of::<Entry>())
                    .ok_or(ForwardError::Capacity)?
                    + ingresses.len() * size_of::<Input>()
                    + size_of::<Self>(),
            )
            .ok_or(ForwardError::Capacity)?;
        let mut inputs = Vec::with_capacity(ingresses.len());
        let aggregate = FragmentLimits::default();
        for (index, &identity) in ingresses.iter().enumerate() {
            let limits = FragmentLimits {
                max_entries: aggregate.max_entries / ingresses.len()
                    + usize::from(index < aggregate.max_entries % ingresses.len()),
                max_bytes: aggregate.max_bytes / ingresses.len()
                    + usize::from(index < aggregate.max_bytes % ingresses.len()),
                ..aggregate
            };
            let transit =
                Transit::new(Arc::clone(&budget), limits).ok_or(ForwardError::Capacity)?;
            inputs.push(Input { identity, transit });
        }
        Ok(Self {
            inputs,
            budget,
            flows: Vec::with_capacity(max_flows),
            max_flows,
            _metadata: metadata,
        })
    }

    /// Execution ownership only, not a firewall grant or proof of TCP establishment.
    /// Reverse identity requires a registered logical egress; traffic class is not a tuple.
    /// Unleased idle owners expire at `now` even before the next maintenance sweep.
    pub fn retains(&self, query: RouteQuery, now: Instant) -> bool {
        self.flows
            .iter()
            .any(|entry| entry.flow.standalone && entry.flow.matches(query) && entry.retained(now))
    }

    /// Copies only after validation; RX borrowed from AF_XDP is no longer accessible when
    /// this call returns. Fragment completions reuse the existing funded packet owner.
    pub fn receive(
        &mut self,
        ingress: Ingress,
        now: Instant,
        bytes: &[u8],
    ) -> Result<Option<Packet>, ForwardError> {
        let input = self
            .inputs
            .iter_mut()
            .find(|input| input.identity == ingress)
            .ok_or(ForwardError::Provenance)?;
        let owned = match wire::parse_ip(bytes) {
            Err(ParseError::Fragment) => match input
                .transit
                .reassemble(now, bytes)
                .map_err(|_| ForwardError::Packet(ParseError::Fragment))?
            {
                Some(packet) => Some(packet),
                None => return Ok(None),
            },
            Err(error) => return Err(error.into()),
            Ok(_) => None,
        };
        let input = owned.as_ref().map_or(bytes, |packet| packet.as_ref());
        let (ip, query) = inspect(ingress, input)?;
        let metadata = self
            .budget
            .reserve(size_of::<Packet>() + 32)
            .ok_or(ForwardError::Capacity)?;
        let storage = match owned {
            Some(packet) => Bytes::Reassembled(packet),
            None => {
                let charge = self
                    .budget
                    .reserve(ip.payload.end)
                    .ok_or(ForwardError::Capacity)?;
                Bytes::Copied(bytes[..ip.payload.end].into(), charge)
            }
        };
        Ok(Some(Packet {
            bytes: storage,
            ip,
            query,
            input_query: query,
            deadline: now + Duration::from_secs(2),
            _metadata: metadata,
            validated: true,
            binding: None,
            native: None,
            native_quote: None,
        }))
    }

    pub fn prepare(
        &mut self,
        packet: Packet,
        route: Route,
        policy_generation: u64,
        now: Instant,
    ) -> Result<Prepared, ForwardError> {
        if !packet.validated {
            return Err(ForwardError::Provenance);
        }
        if packet
            .binding
            .as_ref()
            .is_some_and(|binding| !binding.is_active() || !binding.is_authorized())
        {
            return Err(ForwardError::Expired);
        }
        if let Some(error) = view::check_route(
            self,
            &packet.ip,
            packet.query,
            wire::PacketView::from_slice(packet.as_ref()),
            packet.ipv6_fragment(),
            route,
            (packet.deadline, now),
        )? {
            return Ok(Prepared::Error { packet, error });
        }
        let flow = self.claim(
            packet.query,
            route.ifindex,
            packet.binding.is_none(),
            policy_generation,
            now,
        )?;
        Ok(Prepared::Forward(ForwardPacket {
            packet: Arc::new(packet),
            flow,
            route,
            offset: 0,
        }))
    }

    fn claim(
        &mut self,
        query: RouteQuery,
        egress: u32,
        standalone: bool,
        generation: u64,
        now: Instant,
    ) -> Result<Arc<Flow>, ForwardError> {
        let reply_ingress = self
            .inputs
            .iter()
            .find(|input| input.identity.ifindex == egress)
            .map(|input| input.identity);
        let mut existing = None;
        // ponytail: bounded 4096-entry lookup; index only after profiling the slow owner.
        for (index, entry) in self.flows.iter_mut().enumerate() {
            if entry.flow.standalone != standalone
                || !entry.flow.matches(query)
                || !entry.retained(now)
            {
                continue;
            }
            entry.last = now;
            if same_transport(&entry.flow.query, &query)
                && entry.flow.reply_ingress == reply_ingress
            {
                existing = Some(index);
            }
        }
        if let Some(index) = existing {
            return Ok(Arc::clone(&self.flows[index].flow));
        }
        if self.flows.len() == self.max_flows {
            self.retire(now);
        }
        if self.flows.len() == self.max_flows {
            return Err(ForwardError::Capacity);
        }
        let charge = self
            .budget
            .reserve(size_of::<Flow>() + 32)
            .ok_or(ForwardError::Capacity)?;
        let flow = Arc::new(Flow {
            query,
            reply_ingress,
            standalone,
            generation,
            _charge: charge,
        });
        self.flows.push(Entry {
            flow: Arc::clone(&flow),
            last: now,
        });
        Ok(flow)
    }

    pub fn error(
        &mut self,
        now: Instant,
        error: TransitError,
        source: IpAddr,
        packet: &Packet,
        out: &mut [u8],
    ) -> Result<Option<usize>, ForwardError> {
        let input = self
            .inputs
            .iter_mut()
            .find(|input| input.identity == packet.query.ingress)
            .ok_or(ForwardError::Provenance)?;
        if packet.ip.proto == wire::PROTO_TCP
            && packet
                .as_ref()
                .get(packet.ip.payload.start + 13)
                .is_some_and(|flags| flags & wire::tcp::RST != 0)
        {
            return Ok(None);
        }
        let overhead = if source.is_ipv4() { 28 } else { 48 };
        let quote_len = out
            .len()
            .saturating_sub(overhead)
            .min(packet.as_ref().len());
        if quote_len < packet.ip.payload.start + 8 {
            return Ok(None);
        }
        Ok(input
            .transit
            .error(now, error, source, &packet.as_ref()[..quote_len], out)?)
    }

    pub fn has_retained_flows(&self) -> bool {
        !self.flows.is_empty()
    }

    pub fn retire(&mut self, now: Instant) {
        self.flows.retain(|entry| entry.retained(now));
        for input in &mut self.inputs {
            input.transit.expire(now);
        }
    }

    pub fn poll_reassembly_timeout(&self) -> Option<Instant> {
        self.inputs
            .iter()
            .filter_map(|input| input.transit.poll_timeout())
            .min()
    }
    pub fn fragments_quiescent(&self) -> bool {
        self.inputs.iter().all(|input| input.transit.is_quiescent())
    }

    pub fn fragment_obligations(&self) -> impl Iterator<Item = FragmentObligation> + Clone + '_ {
        self.inputs.iter().flat_map(|input| {
            input
                .transit
                .fragment_obligations()
                .map(move |(source, destination, protocol)| FragmentObligation {
                    ingress: input.identity,
                    source,
                    destination,
                    protocol,
                })
        })
    }

    /// The quote retains its shared-budget reservation until the ICMP/output owner drops it.
    pub fn poll_expired_quote(&mut self) -> Option<(Ingress, OwnedPacket)> {
        self.inputs.iter_mut().find_map(|input| {
            input
                .transit
                .poll_expired_quote()
                .map(|quote| (input.identity, quote))
        })
    }

    pub fn reassembly_error(
        &mut self,
        ingress: Ingress,
        now: Instant,
        source: IpAddr,
        quote: &OwnedPacket,
        out: &mut [u8],
    ) -> Result<Option<usize>, ForwardError> {
        let input = self
            .inputs
            .iter_mut()
            .find(|input| input.identity == ingress)
            .ok_or(ForwardError::Provenance)?;
        let Some(metadata) = honk_netstack::transit::quote_metadata(quote) else {
            return Ok(None);
        };
        let overhead = if source.is_ipv4() { 28 } else { 48 };
        let quote_len = out.len().saturating_sub(overhead).min(quote.len());
        if quote_len < metadata.header_len + 8 {
            return Ok(None);
        }
        Ok(input.transit.error(
            now,
            TransitError::ReassemblyTimeExceeded,
            source,
            &quote[..quote_len],
            out,
        )?)
    }
}

impl ForwardPacket {
    pub fn route(&self) -> Route {
        self.route
    }
    pub fn deadline(&self) -> Instant {
        self.packet.deadline
    }
    pub fn is_complete(&self) -> bool {
        self.offset == self.packet.ip.payload.end
    }

    /// A too-small output changes neither cursor nor TTL. Only materialized copies are
    /// decremented; retries and restored fragments derive from untouched ingress bytes.
    pub fn write_next(&mut self, out: &mut [u8]) -> Option<(usize, ForwardLease)> {
        let length = self.write_next_segments(&mut [out], &[])?;
        Some((length, self.lease()))
    }

    pub fn next_len(&self) -> Option<usize> {
        view::shape(
            &self.packet.ip,
            self.packet.ipv6_fragment(),
            self.route,
            self.offset,
        )
        .map(|(header, payload)| header + payload)
    }
    pub fn lease(&self) -> ForwardLease {
        ForwardLease {
            packet: Some(Arc::clone(&self.packet)),
            flow: Arc::clone(&self.flow),
            _native: None,
        }
    }
    pub fn write_next_segments(&mut self, out: &mut [&mut [u8]], prefix: &[u8]) -> Option<usize> {
        if self
            .packet
            .binding
            .as_ref()
            .is_some_and(|binding| !binding.is_active())
        {
            return None;
        }
        view::write_next(
            wire::PacketView::from_slice(self.packet.as_ref().as_ref()),
            &self.packet.ip,
            self.packet.ipv6_fragment(),
            self.route,
            self.packet
                .native
                .as_ref()
                .map(crate::firewall::NativeLease::output_id),
            &mut self.offset,
            out,
            prefix,
        )
    }
}

fn same_transport(left: &RouteQuery, right: &RouteQuery) -> bool {
    left.ingress == right.ingress
        && left.source == right.source
        && left.destination == right.destination
        && left.protocol == right.protocol
        && left.ports == right.ports
}

fn inspect(ingress: Ingress, input: &[u8]) -> Result<(IpPacket, RouteQuery), ForwardError> {
    view::inspect_view(ingress, wire::PacketView::from_slice(input))
}

fn validate_options(packet: &[u8], ip: &IpPacket) -> Result<(), ParseError> {
    if ip.src.is_ipv4() {
        if packet[6] & 0x80 != 0 {
            return Err(ParseError::Malformed);
        }
        let mut options = &packet[20..ip.payload.start];
        while let Some((&kind, rest)) = options.split_first() {
            match kind {
                0 => break,
                1 => options = rest,
                _ => {
                    let length = usize::from(*rest.first().ok_or(ParseError::Malformed)?);
                    if length < 2 || length > options.len() {
                        return Err(ParseError::Malformed);
                    }
                    // Source route, record route, timestamp and Router Alert require an
                    // independent execution contract; never forward them as inert bytes.
                    return Err(ParseError::Unsupported);
                }
            }
        }
    } else if ip.payload.start != 40 || packet[1] & 15 != 0 || packet[2..4] != [0, 0] {
        // The shared parser bounds extensions. Router-specific option execution is not
        // claimed; fragments themselves have already been removed by shared reassembly.
        return Err(ParseError::Unsupported);
    }
    Ok(())
}
