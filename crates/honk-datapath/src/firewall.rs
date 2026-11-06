//! Stateful admission and IPv4 translation for the single CoreForward owner.
//! No device, route lookup, packet allocation or independent packet executor lives here.
use crate::forward::{FragmentObligation, Ingress, TCP_IDLE_TIMEOUT, UDP_IDLE_TIMEOUT};
use honk_netstack::{
    MemoryBudget, MemoryReservation,
    wire::{self, ParseError, checksum::Checksum, tcp},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuple {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
}
impl Tuple {
    pub fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            ..self
        }
    }
    fn fragment_domain(self, other: Self) -> bool {
        self.source == other.source
            && self.destination == other.destination
            && self.protocol == other.protocol
    }
}

#[derive(Clone, Copy, Debug)]
struct TcpFacts {
    seq: u32,
    ack: u32,
    flags: u8,
}

#[derive(Clone, Copy, Debug)]
struct Ipv4Facts {
    id: u16,
    fragmentable: bool,
}
impl Ipv4Facts {
    fn from_header(bytes: &[u8]) -> Option<Self> {
        (bytes[0] >> 4 == 4).then(|| Self {
            id: u16::from_be_bytes([bytes[4], bytes[5]]),
            fragmentable: u16::from_be_bytes([bytes[6], bytes[7]]) & 0x4000 == 0,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Quote {
    tuple: Tuple,
    ipv4: Option<Ipv4Facts>,
    nonfirst: bool,
}
impl Quote {
    fn parse(bytes: &[u8]) -> Result<Self, FirewallError> {
        let tuple = quoted_tuple(bytes)?;
        let ipv4 = Ipv4Facts::from_header(bytes);
        Ok(Self {
            tuple,
            ipv4,
            nonfirst: ipv4.is_some() && u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff != 0,
        })
    }
    fn matches(self, tuple: Tuple) -> bool {
        self.tuple == tuple
            || (self.nonfirst
                && self.tuple.source == tuple.source
                && self.tuple.destination == tuple.destination
                && self.tuple.protocol == tuple.protocol)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Facts {
    pub tuple: Tuple,
    tcp: Option<TcpFacts>,
    payload_len: usize,
    echo_reply: bool,
    ipv4: Option<Ipv4Facts>,
    quote: Option<Quote>,
}
impl Facts {
    /// Validate complete packet/checksums before any table mutation. Fragments must use
    /// CoreForward's shared reassembler first; their missing ports are never invented.
    pub fn parse(bytes: &[u8]) -> Result<Self, FirewallError> {
        let ip = wire::parse_ip(bytes)?;
        Self::parse_parts(bytes, &ip, false)
    }
    /// CoreForward already validated transport bounds and checksums before allocating
    /// this typed owner. Reuse that proof instead of rescanning the packet payload.
    pub fn from_packet(packet: &crate::forward::Packet) -> Result<Self, FirewallError> {
        if !packet.is_validated() {
            return Err(FirewallError::Denied);
        }
        Self::parse_parts(packet.as_ref(), packet.ip(), true)
    }
    /// Restore the received tuple and ID when forwarding instead generates an ICMP error.
    pub fn restore(&self, bytes: &mut [u8]) -> Result<(), FirewallError> {
        rewrite_tuple(bytes, self.tuple, self.ipv4.map(|ipv4| ipv4.id))
    }
    fn parse_parts(
        bytes: &[u8],
        ip: &wire::IpPacket,
        validated: bool,
    ) -> Result<Self, FirewallError> {
        if !validated
            && (!honk_netstack::transit::unicast(ip.src)
                || !honk_netstack::transit::unicast(ip.dst))
        {
            return Err(FirewallError::Denied);
        }
        let segment = &bytes[ip.payload.clone()];
        let mut tuple = Tuple {
            source: ip.src,
            destination: ip.dst,
            protocol: ip.proto,
            source_port: 0,
            destination_port: 0,
        };
        let mut facts = Self {
            tuple,
            tcp: None,
            payload_len: 0,
            echo_reply: false,
            ipv4: Ipv4Facts::from_header(bytes),
            quote: None,
        };
        match ip.proto {
            wire::PROTO_TCP => {
                let (header, offset) = tcp::parse(segment)?;
                if !validated && !tcp::verify_checksum(ip.src, ip.dst, segment) {
                    return Err(ParseError::Checksum.into());
                }
                tuple.source_port = header.src_port;
                tuple.destination_port = header.dst_port;
                facts.tcp = Some(TcpFacts {
                    seq: header.seq,
                    ack: header.ack,
                    flags: header.flags,
                });
                facts.payload_len = segment.len() - offset;
            }
            wire::PROTO_UDP => {
                let (source, destination, _) = wire::udp::parse(segment)?;
                if !validated && !wire::udp::verify_checksum(ip.src, ip.dst, segment) {
                    return Err(ParseError::Checksum.into());
                }
                tuple.source_port = source;
                tuple.destination_port = destination;
            }
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 => {
                if segment.len() < 8 {
                    return Err(ParseError::Malformed.into());
                }
                if (ip.proto == wire::PROTO_ICMP) != ip.src.is_ipv4() {
                    return Err(FirewallError::Unsupported);
                }
                if !validated {
                    let mut checksum = if ip.proto == wire::PROTO_ICMP {
                        Checksum::new()
                    } else {
                        Checksum::pseudo(ip.src, ip.dst, ip.proto, segment.len())
                    };
                    checksum.add(segment);
                    if checksum.finish() != 0 {
                        return Err(ParseError::Checksum.into());
                    }
                }
                match (ip.proto, segment[0], segment[1]) {
                    (wire::PROTO_ICMP, 8 | 0, 0) | (wire::PROTO_ICMPV6, 128 | 129, 0) => {
                        let id = u16::from_be_bytes([segment[4], segment[5]]);
                        tuple.source_port = id;
                        tuple.destination_port = id;
                        facts.echo_reply = segment[0] == 0 || segment[0] == 129;
                    }
                    (wire::PROTO_ICMP, 3 | 11 | 12, _) => {
                        facts.quote = Some(Quote::parse(&segment[8..icmp_quote_end(segment)?])?)
                    }
                    (wire::PROTO_ICMPV6, 1..=4, _) => {
                        facts.quote = Some(Quote::parse(&segment[8..])?)
                    }
                    _ => return Err(FirewallError::Unsupported),
                }
            }
            _ => return Err(FirewallError::Unsupported),
        }
        facts.tuple = tuple;
        if facts
            .quote
            .is_some_and(|quote| quote.tuple.source.is_ipv4() != ip.src.is_ipv4())
        {
            return Err(FirewallError::Unsupported);
        }
        Ok(facts)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationNat {
    pub address: Ipv4Addr,
    pub port: Option<u16>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortPool {
    pub first: u16,
    pub last: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceNat {
    None,
    Snat {
        address: Ipv4Addr,
        ports: Option<PortPool>,
    },
    Masquerade {
        ports: PortPool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressAddress {
    pub ifindex: u32,
    pub address: Ipv4Addr,
    pub generation: u64,
}

pub struct Admission<'a> {
    pub ingress: Ingress,
    pub reply_ingress: Ingress,
    pub facts: &'a Facts,
    pub dnat: Option<DestinationNat>,
    pub snat: SourceNat,
    pub egress: Option<EgressAddress>,
    pub received_at: Instant,
    pub now: Instant,
}

#[derive(Debug)]
pub enum FirewallError {
    Packet(ParseError),
    Unsupported,
    Denied,
    Capacity,
    Conflict,
    Exhausted,
    Stale,
    AddressUnavailable,
}
impl From<ParseError> for FirewallError {
    fn from(error: ParseError) -> Self {
        Self::Packet(error)
    }
}
impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for FirewallError {}

struct Binding {
    ingress: Ingress,
    reply_ingress: Ingress,
    original: Tuple,
    destination: Tuple,
    translated: Tuple,
    epoch: u64,
    masquerade: Option<EgressAddress>,
    active: AtomicBool,
    fragment_pending: AtomicBool,
    _charge: MemoryReservation,
}
impl Binding {
    fn aliases(&self) -> [(Ingress, Tuple); 6] {
        [
            (self.ingress, self.original),
            (self.ingress, self.original.reverse()),
            (self.ingress, self.destination),
            (self.ingress, self.destination.reverse()),
            (self.reply_ingress, self.translated),
            (self.reply_ingress, self.translated.reverse()),
        ]
    }
    fn domain(&self, ingress: Ingress) -> bool {
        self.ingress.scope == ingress.scope && self.ingress.namespace == ingress.namespace
    }
    fn related_tuples(&self, quoted_reply: bool) -> (Tuple, Tuple) {
        if quoted_reply {
            (self.original.reverse(), self.translated.reverse())
        } else {
            (self.translated, self.original)
        }
    }
    fn matches_fragment(&self, fragment: FragmentObligation) -> bool {
        let matches = |ingress, tuple: Tuple| {
            fragment.ingress == ingress
                && fragment.source == tuple.source
                && fragment.destination == tuple.destination
                && fragment.protocol == tuple.protocol
        };
        matches(self.ingress, self.original)
            || matches(self.reply_ingress, self.translated.reverse())
            // An ICMP error's intermediate sender need not be the quoted peer.
            || (matches!(fragment.protocol, wire::PROTO_ICMP | wire::PROTO_ICMPV6)
                && ((fragment.ingress == self.reply_ingress
                    && fragment.destination == self.translated.source)
                    || (fragment.ingress == self.ingress
                        && fragment.destination == self.original.destination)))
    }
    fn fragments_retained(&self, exported: &[Arc<RetainedFragment>]) -> bool {
        self.fragment_pending.load(Ordering::Relaxed)
            || exported
                .iter()
                .any(|retained| self.matches_fragment(retained.obligation))
    }
}
#[derive(Clone, Copy)]
enum Direction {
    Original,
    Reply,
    Related {
        quoted_reply: bool,
        outer_source: IpAddr,
    },
}
/// Clone pins the allocation and every alias through actual output/CQ retirement.
#[derive(Clone)]
pub struct BindingLease {
    binding: Arc<Binding>,
    direction: Direction,
    identity: Option<Arc<DatagramIdentity>>,
    quoted_identity: Option<Arc<DatagramIdentity>>,
    _native_identity: Option<NativeLease>,
    authorized: bool,
}
impl BindingLease {
    pub fn is_current(&self, epoch: u64) -> bool {
        self.binding.epoch == epoch && self.binding.active.load(Ordering::Acquire)
    }
    pub fn is_active(&self) -> bool {
        self.binding.active.load(Ordering::Acquire)
    }
    pub fn is_authorized(&self) -> bool {
        self.authorized
    }
    pub fn translation_required(&self) -> bool {
        self.binding.original != self.binding.translated
            || self.identity.is_some()
            || self.quoted_identity.is_some()
    }
    pub fn egress_ingress(&self) -> Ingress {
        match self.direction {
            Direction::Original => self.binding.reply_ingress,
            Direction::Reply => self.binding.ingress,
            Direction::Related { quoted_reply, .. } => {
                if quoted_reply {
                    self.binding.reply_ingress
                } else {
                    self.binding.ingress
                }
            }
        }
    }
    pub fn masquerade(&self) -> Option<EgressAddress> {
        self.binding.masquerade
    }
    pub fn before_route(&self) -> Tuple {
        match self.direction {
            Direction::Original => self.binding.destination,
            Direction::Reply => Tuple {
                destination: self.binding.original.source,
                destination_port: self.binding.original.source_port,
                ..self.binding.translated.reverse()
            },
            Direction::Related {
                quoted_reply,
                outer_source,
            } => {
                let destination = if quoted_reply {
                    self.binding.translated.destination
                } else {
                    self.binding.original.source
                };
                Tuple {
                    source: outer_source,
                    destination,
                    protocol: if destination.is_ipv4() {
                        wire::PROTO_ICMP
                    } else {
                        wire::PROTO_ICMPV6
                    },
                    source_port: 0,
                    destination_port: 0,
                }
            }
        }
    }
    pub fn after_route(&self) -> Tuple {
        match self.direction {
            Direction::Original => self.binding.translated,
            Direction::Reply => self.binding.original.reverse(),
            Direction::Related { .. } => self.before_route(),
        }
    }
    pub fn rewrite(&self, bytes: &mut [u8], before_route: bool) -> Result<(), FirewallError> {
        if !self.authorized || !self.binding.active.load(Ordering::Acquire) {
            return Err(FirewallError::Stale);
        }
        if let Direction::Related { quoted_reply, .. } = self.direction {
            let (quote, restored) = self.binding.related_tuples(quoted_reply);
            if quote != restored || self.quoted_identity.is_some() {
                repair_icmp_quote(
                    bytes,
                    quote,
                    restored,
                    self.quoted_identity
                        .as_ref()
                        .map(|identity| (identity.output_id, identity.input_id)),
                )?;
            }
        }
        if self.binding.original == self.binding.translated
            && !matches!(self.direction, Direction::Related { .. })
        {
            if !before_route && let Some(identity) = &self.identity {
                let ip = wire::parse_ip(bytes)?;
                if !ip.src.is_ipv4() {
                    return Err(FirewallError::Unsupported);
                }
                bytes[4..6].copy_from_slice(&identity.output_id.to_be_bytes());
                bytes[10..12].fill(0);
                let checksum = wire::checksum::checksum(&bytes[..ip.payload.start]);
                bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            return Ok(());
        }
        rewrite_tuple(
            bytes,
            if before_route {
                self.before_route()
            } else {
                self.after_route()
            },
            if before_route {
                None
            } else {
                self.identity.as_ref().map(|identity| identity.output_id)
            },
        )
    }
}

#[derive(Clone, Copy)]
struct SynProof {
    sequence: u32,
    end: u32,
    bare: bool,
    with_ack: bool,
}
impl SynProof {
    fn acknowledges(self, value: u32) -> bool {
        value.wrapping_sub(self.sequence.wrapping_add(1))
            <= self.end.wrapping_sub(self.sequence.wrapping_add(1))
    }
    fn matches(self, sequence: u32, payload_len: usize) -> bool {
        self.sequence == sequence
            && self.acknowledges(sequence.wrapping_add(1).wrapping_add(payload_len as u32))
    }
}
#[derive(Clone, Copy)]
enum State {
    Opening {
        syn: [Option<SynProof>; 2],
        acknowledged: [bool; 2],
    },
    Established {
        syn: [Option<SynProof>; 2],
    },
    Datagram,
    Closing,
}
struct Entry {
    binding: Arc<Binding>,
    state: State,
    received_at: Instant,
    last: Instant,
}

// RFC 6864's conventional MDL, not a guarantee for arbitrary longer remote queues/delays.
const IPV4_ID_LIFETIME: Duration = Duration::from_secs(120);
const IPV4_ID_WORDS: usize = 1024;

fn overflow_lifetime() -> Duration {
    // CoreForward keeps this default timeout; completed quotes pin before any queued work.
    IPV4_ID_LIFETIME + honk_netstack::FragmentLimits::default().timeout
}

#[derive(Clone, Copy)]
struct WireDomain {
    ingress: Ingress,
    output: Tuple,
}
impl WireDomain {
    fn matches(self, ingress: Ingress, output: Tuple) -> bool {
        self.ingress.scope == ingress.scope
            && self.ingress.namespace == ingress.namespace
            && self.output.fragment_domain(output)
    }
    fn matches_fragment(self, egress: Ingress, fragment: FragmentObligation) -> bool {
        (fragment.ingress == self.ingress
            && fragment.source == self.output.source
            && fragment.destination == self.output.destination
            && fragment.protocol == self.output.protocol)
            || (fragment.ingress == egress
                && fragment.protocol == wire::PROTO_ICMP
                && fragment.destination == self.output.source)
    }
}
struct DatagramIdentity {
    binding: Option<Arc<Binding>>,
    domain: WireDomain,
    quote_ingress: Ingress,
    reply: Option<bool>,
    input_id: u16,
    output_id: u16,
    _charge: MemoryReservation,
}
struct IdentityEntry {
    identity: Arc<DatagramIdentity>,
    retired_at: Option<Instant>,
    fragment_pending: bool,
}
struct NativeIdentity {
    domain: WireDomain,
    quote_ingress: Ingress,
    id: u16,
    _charge: MemoryReservation,
}
struct NativeEntry {
    identity: Arc<NativeIdentity>,
    retired_at: Option<Instant>,
    fragment_pending: bool,
}
struct NativeOverflow {
    counts: Vec<AtomicU32>,
    retired: Vec<AtomicU64>,
    _charge: MemoryReservation,
}
struct OverflowLease {
    owner: Arc<NativeOverflow>,
    id: u16,
}
impl Clone for OverflowLease {
    fn clone(&self) -> Self {
        self.owner.counts[usize::from(self.id)]
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .expect("native ID output ownership exhausted");
        Self {
            owner: Arc::clone(&self.owner),
            id: self.id,
        }
    }
}
impl Drop for OverflowLease {
    fn drop(&mut self) {
        let previous = self.owner.counts[usize::from(self.id)].fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0);
    }
}
#[derive(Clone)]
enum NativeRetention {
    Exact(Arc<NativeIdentity>),
    Overflow(OverflowLease),
    Remapped(Arc<DatagramIdentity>),
}
/// Native output history owns no firewall grant and survives policy revocation.
#[derive(Clone)]
pub struct NativeLease {
    retained: NativeRetention,
}
impl NativeLease {
    pub fn output_id(&self) -> u16 {
        match &self.retained {
            NativeRetention::Exact(identity) => identity.id,
            NativeRetention::Overflow(lease) => lease.id,
            NativeRetention::Remapped(identity) => identity.output_id,
        }
    }
    pub fn is_exact(&self) -> bool {
        !matches!(self.retained, NativeRetention::Overflow(_))
    }
    pub fn rewrite(&self, bytes: &mut [u8]) -> Result<(), FirewallError> {
        rewrite_id(bytes, self.output_id())
    }
}
/// An ICMP quote ID repair or native overflow pin, never related-flow admission.
#[derive(Clone)]
pub struct NativeQuoteLease {
    identity: Option<Arc<DatagramIdentity>>,
    _overflow: Option<OverflowLease>,
}
impl NativeQuoteLease {
    pub fn rewrite(&self, bytes: &mut [u8]) -> Result<(), FirewallError> {
        let Some(identity) = &self.identity else {
            return Ok(());
        };
        repair_icmp_quote(
            bytes,
            identity.domain.output,
            identity.domain.output,
            Some((identity.output_id, identity.input_id)),
        )?;
        let ip = wire::parse_ip(bytes)?;
        let checksum_field = ip.payload.start + 2;
        bytes[checksum_field..checksum_field + 2].fill(0);
        let checksum = wire::checksum::checksum(&bytes[ip.payload]);
        bytes[checksum_field..checksum_field + 2].copy_from_slice(&checksum.to_be_bytes());
        Ok(())
    }
}

struct RetainedFragment {
    obligation: FragmentObligation,
    _charge: MemoryReservation,
}
/// An exported timeout quote retains only its possible aliases/IDs, never a traffic grant.
#[derive(Clone)]
pub struct FragmentLease {
    _retained: Arc<RetainedFragment>,
}

/// One binding directory with at most `min(capacity * 64, 65536)` retained IPv4 NAT IDs.
/// Only actual ID translations spend the managed pool; native history saturation never drops plain output.
/// IDs and aliases stay reserved through held outputs/quotes and a subsequent 120s MDL.
pub struct Firewall {
    entries: Vec<Entry>,
    retained_fragments: Vec<Arc<RetainedFragment>>,
    capacity: usize,
    identities: Vec<IdentityEntry>,
    identity_capacity: usize,
    native_history: Vec<NativeEntry>,
    native_overflow: Arc<NativeOverflow>,
    overflow_bits: Vec<u64>,
    overflow_active: usize,
    overflow_origin: Option<Instant>,
    native_bits: Vec<u64>,
    id_bits: Vec<u64>,
    next_id_word: usize,
    epoch: u64,
    budget: Arc<MemoryBudget>,
    _state_charge: Option<MemoryReservation>,
    _charge: MemoryReservation,
}
impl Firewall {
    pub fn new(
        budget: Arc<MemoryBudget>,
        capacity: usize,
        epoch: u64,
    ) -> Result<Self, FirewallError> {
        if epoch == 0 {
            return Err(FirewallError::Capacity);
        }
        let mut table = Self::new_history(budget, capacity, epoch)?;
        table.ensure_state()?;
        Ok(table)
    }
    /// Keep this owner across policy=None/Some; history alone allocates no conntrack table.
    pub fn new_history(
        budget: Arc<MemoryBudget>,
        capacity: usize,
        epoch: u64,
    ) -> Result<Self, FirewallError> {
        if capacity == 0 || capacity > 4096 {
            return Err(FirewallError::Capacity);
        }
        let identity_capacity = (capacity * 64).min(65536);
        let bytes = identity_capacity * size_of::<NativeEntry>()
            + capacity * size_of::<Arc<RetainedFragment>>()
            + 2 * IPV4_ID_WORDS * size_of::<u64>()
            + size_of::<Self>();
        let charge = budget.reserve(bytes).ok_or(FirewallError::Capacity)?;
        let overflow_charge = budget
            .reserve(
                size_of::<NativeOverflow>()
                    + 2 * size_of::<usize>()
                    + 65536 * (size_of::<AtomicU32>() + size_of::<AtomicU64>()),
            )
            .ok_or(FirewallError::Capacity)?;
        Ok(Self {
            entries: Vec::new(),
            retained_fragments: Vec::with_capacity(capacity),
            capacity,
            identities: Vec::new(),
            identity_capacity,
            native_history: Vec::with_capacity(identity_capacity),
            native_overflow: Arc::new(NativeOverflow {
                counts: (0..65536).map(|_| AtomicU32::new(0)).collect(),
                retired: (0..65536).map(|_| AtomicU64::new(0)).collect(),
                _charge: overflow_charge,
            }),
            overflow_bits: vec![0; IPV4_ID_WORDS],
            overflow_active: 0,
            overflow_origin: None,
            native_bits: vec![0; IPV4_ID_WORDS],
            id_bits: Vec::new(),
            next_id_word: 0,
            epoch,
            budget,
            _state_charge: None,
            _charge: charge,
        })
    }
    fn ensure_state(&mut self) -> Result<(), FirewallError> {
        if self._state_charge.is_some() {
            return Ok(());
        }
        let bytes = self.capacity * size_of::<Entry>()
            + self.identity_capacity * size_of::<IdentityEntry>()
            + IPV4_ID_WORDS * size_of::<u64>();
        let charge = self.budget.reserve(bytes).ok_or(FirewallError::Capacity)?;
        self.entries = Vec::with_capacity(self.capacity);
        self.identities = Vec::with_capacity(self.identity_capacity);
        self.id_bits = vec![0; IPV4_ID_WORDS];
        self._state_charge = Some(charge);
        Ok(())
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Missing fragment ports retain only the address/protocol domains they could complete.
    pub fn set_fragment_obligations(&mut self, pending: impl Iterator<Item = FragmentObligation>) {
        for entry in &self.entries {
            entry
                .binding
                .fragment_pending
                .store(false, Ordering::Relaxed);
        }
        for entry in &mut self.identities {
            entry.fragment_pending = false;
        }
        for entry in &mut self.native_history {
            entry.fragment_pending = false;
        }
        for fragment in pending {
            for entry in &self.entries {
                if entry.binding.matches_fragment(fragment) {
                    entry
                        .binding
                        .fragment_pending
                        .store(true, Ordering::Relaxed);
                }
            }
            for entry in &mut self.identities {
                if entry.identity.binding.is_none()
                    && entry
                        .identity
                        .domain
                        .matches_fragment(entry.identity.quote_ingress, fragment)
                {
                    entry.fragment_pending = true;
                }
            }
            for entry in &mut self.native_history {
                if entry
                    .identity
                    .domain
                    .matches_fragment(entry.identity.quote_ingress, fragment)
                {
                    entry.fragment_pending = true;
                }
            }
        }
    }
    /// Called only on successful policy publication; never on a rejected candidate.
    pub fn revoke(&mut self, epoch: u64) {
        for entry in &self.entries {
            entry.binding.active.store(false, Ordering::Release);
        }
        self.epoch = epoch;
    }
    pub fn invalidate_address(&mut self, ifindex: u32, address: Ipv4Addr) {
        for entry in &self.entries {
            if entry
                .binding
                .masquerade
                .is_some_and(|value| value.ifindex == ifindex && value.address == address)
            {
                entry.binding.active.store(false, Ordering::Release);
            }
        }
    }
    pub fn invalidate_address_generation(&mut self, generation: u64) {
        for entry in &self.entries {
            if entry
                .binding
                .masquerade
                .is_some_and(|address| address.generation != generation)
            {
                entry.binding.active.store(false, Ordering::Release);
            }
        }
    }

    pub fn expire(&mut self, now: Instant) {
        self.retained_fragments
            .retain(|entry| Arc::strong_count(entry) != 1);
        self.identities.retain_mut(|entry| {
            if entry.fragment_pending
                || entry
                    .identity
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.fragments_retained(&self.retained_fragments))
                || self.retained_fragments.iter().any(|retained| {
                    entry
                        .identity
                        .domain
                        .matches_fragment(entry.identity.quote_ingress, retained.obligation)
                })
                || Arc::strong_count(&entry.identity) != 1
            {
                entry.retired_at = None;
                return true;
            }
            // Start the MDL only after the last packet/quote/CQ owner is observed retired.
            let retired_at = *entry.retired_at.get_or_insert(now);
            if now.saturating_duration_since(retired_at) < IPV4_ID_LIFETIME {
                return true;
            }
            let id = usize::from(entry.identity.output_id);
            self.id_bits[id / 64] &= !(1u64 << (id % 64));
            false
        });
        self.native_history.retain_mut(|entry| {
            if entry.fragment_pending
                || self.retained_fragments.iter().any(|retained| {
                    entry
                        .identity
                        .domain
                        .matches_fragment(entry.identity.quote_ingress, retained.obligation)
                })
                || Arc::strong_count(&entry.identity) != 1
            {
                entry.retired_at = None;
                return true;
            }
            let retired_at = *entry.retired_at.get_or_insert(now);
            if now.saturating_duration_since(retired_at) < IPV4_ID_LIFETIME {
                return true;
            }
            false
        });
        let origin = *self.overflow_origin.get_or_insert(now);
        let tick = now
            .saturating_duration_since(origin)
            .as_nanos()
            .min(u128::from(u64::MAX - 1)) as u64
            + 1;
        let lifetime = overflow_lifetime().as_nanos() as u64;
        // Only the single owner publishes retirement, after observing the final release.
        if self.overflow_active != 0 {
            for (word, bits) in self.overflow_bits.iter_mut().enumerate() {
                let mut pending = *bits;
                while pending != 0 {
                    let bit = pending.trailing_zeros() as usize;
                    pending &= pending - 1;
                    let id = word * 64 + bit;
                    if self.native_overflow.counts[id].load(Ordering::Acquire) != 0 {
                        self.native_overflow.retired[id].store(0, Ordering::Release);
                    } else {
                        let retired = &self.native_overflow.retired[id];
                        let mut retired_at = retired.load(Ordering::Acquire);
                        if retired_at == 0 {
                            retired_at = tick;
                            retired.store(tick, Ordering::Release);
                        }
                        if tick.saturating_sub(retired_at) >= lifetime {
                            *bits &= !(1u64 << bit);
                            self.overflow_active -= 1;
                        }
                    }
                }
            }
        }
        self.entries.retain(|entry| {
            let ttl = match entry.state {
                State::Established { .. } => TCP_IDLE_TIMEOUT,
                State::Datagram => UDP_IDLE_TIMEOUT,
                _ => Duration::from_secs(30),
            };
            if now.saturating_duration_since(entry.last) >= ttl {
                entry.binding.active.store(false, Ordering::Release);
            }
            entry.binding.active.load(Ordering::Acquire)
                || entry.binding.fragments_retained(&self.retained_fragments)
                || Arc::strong_count(&entry.binding) != 1
        });
    }
    pub fn lookup(
        &mut self,
        ingress: Ingress,
        facts: &Facts,
        now: Instant,
    ) -> Result<Option<BindingLease>, FirewallError> {
        self.lookup_inner(ingress, facts, now, true)
    }
    /// Pins a completing packet without spending an ID or renewing the binding before policy.
    pub fn pin(
        &mut self,
        ingress: Ingress,
        facts: &Facts,
        now: Instant,
    ) -> Result<Option<BindingLease>, FirewallError> {
        self.lookup_inner(ingress, facts, now, false)
    }
    /// Retain a partial timeout quote without renewing state or authorizing output.
    pub fn retain_fragment(
        &mut self,
        obligation: FragmentObligation,
    ) -> Result<Option<FragmentLease>, FirewallError> {
        self.retained_fragments
            .retain(|entry| Arc::strong_count(entry) != 1);
        if !self
            .entries
            .iter()
            .any(|entry| entry.binding.matches_fragment(obligation))
            && !self.identities.iter().any(|entry| {
                entry
                    .identity
                    .domain
                    .matches_fragment(entry.identity.quote_ingress, obligation)
            })
            && !self.native_history.iter().any(|entry| {
                entry
                    .identity
                    .domain
                    .matches_fragment(entry.identity.quote_ingress, obligation)
            })
        {
            return Ok(None);
        }
        if self.retained_fragments.len() == self.capacity {
            return Err(FirewallError::Capacity);
        }
        let charge = self
            .budget
            .reserve(size_of::<RetainedFragment>() + 2 * size_of::<usize>())
            .ok_or(FirewallError::Capacity)?;
        let retained = Arc::new(RetainedFragment {
            obligation,
            _charge: charge,
        });
        self.retained_fragments.push(Arc::clone(&retained));
        Ok(Some(FragmentLease {
            _retained: retained,
        }))
    }
    fn lookup_inner(
        &mut self,
        ingress: Ingress,
        facts: &Facts,
        now: Instant,
        authorize: bool,
    ) -> Result<Option<BindingLease>, FirewallError> {
        self.expire(now);
        if let Some(quote) = facts.quote {
            for index in 0..self.entries.len() {
                let entry = &self.entries[index];
                let binding = &entry.binding;
                if !binding.domain(ingress) {
                    continue;
                }
                let (quoted_reply, expected_ingress) = if quote.matches(binding.translated)
                    && facts.tuple.destination == binding.translated.source
                {
                    (false, binding.reply_ingress)
                } else if quote.matches(binding.original.reverse())
                    && facts.tuple.destination == binding.original.destination
                {
                    (true, binding.ingress)
                } else {
                    continue;
                };
                if ingress != expected_ingress {
                    continue;
                }
                let identity_index = quote
                    .ipv4
                    .filter(|ipv4| ipv4.fragmentable || quote.nonfirst)
                    .and_then(|ipv4| {
                        self.identities.iter().position(|entry| {
                            entry
                                .identity
                                .binding
                                .as_ref()
                                .is_some_and(|owner| Arc::ptr_eq(owner, binding))
                                && entry.identity.reply == Some(quoted_reply)
                                && ipv4.id == entry.identity.output_id
                        })
                    });
                if identity_index.is_none()
                    && (quote.nonfirst
                        || (binding.original != binding.translated
                            && quote.ipv4.is_some_and(|ipv4| ipv4.fragmentable)))
                {
                    continue;
                }
                if !binding.active.load(Ordering::Acquire) {
                    return Err(FirewallError::Stale);
                }
                if now < entry.received_at {
                    return Err(FirewallError::Denied);
                }
                let quoted_identity =
                    identity_index.map(|index| Arc::clone(&self.identities[index].identity));
                let (_, restored) = binding.related_tuples(quoted_reply);
                let outer_source = if facts.tuple.source == quote.tuple.destination {
                    restored.destination
                } else {
                    facts.tuple.source
                };
                let binding = Arc::clone(binding);
                let direction = Direction::Related {
                    quoted_reply,
                    outer_source,
                };
                if !authorize {
                    return Ok(Some(BindingLease {
                        binding,
                        direction,
                        identity: None,
                        quoted_identity,
                        _native_identity: None,
                        authorized: false,
                    }));
                }
                let lease = self.lease(binding, direction, facts, quoted_identity)?;
                if let Some(index) = identity_index {
                    self.identities[index].retired_at = None;
                }
                return Ok(Some(lease));
            }
            return if authorize {
                Err(FirewallError::Denied)
            } else {
                Ok(None)
            };
        }
        let mut wrong_reply_ingress = false;
        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            if !entry.binding.domain(ingress) {
                continue;
            }
            let direction =
                if facts.tuple == entry.binding.original && ingress == entry.binding.ingress {
                    Direction::Original
                } else if facts.tuple == entry.binding.translated.reverse()
                    && ingress == entry.binding.reply_ingress
                {
                    Direction::Reply
                } else {
                    wrong_reply_ingress |= facts.tuple == entry.binding.translated.reverse();
                    if entry.binding.aliases().contains(&(ingress, facts.tuple)) {
                        return Err(FirewallError::Conflict);
                    }
                    continue;
                };
            if !entry.binding.active.load(Ordering::Acquire) {
                return Err(FirewallError::Stale);
            }
            if now < entry.received_at {
                return Err(FirewallError::Denied);
            }
            let reply = matches!(direction, Direction::Reply);
            let next = transition(entry.state, facts, reply)?;
            let binding = Arc::clone(&entry.binding);
            if !authorize {
                return Ok(Some(BindingLease {
                    binding,
                    direction,
                    identity: None,
                    quoted_identity: None,
                    _native_identity: None,
                    authorized: false,
                }));
            }
            let lease = self.lease(binding, direction, facts, None)?;
            let entry = &mut self.entries[index];
            entry.state = next;
            entry.last = entry.last.max(now);
            return Ok(Some(lease));
        }
        if authorize && wrong_reply_ingress {
            Err(FirewallError::Denied)
        } else {
            Ok(None)
        }
    }
    /// Both firewall stages must have allowed the new original before this atomic
    /// allocation. No owner/port is published on conflict, exhaustion or budget failure.
    /// `received_at` fences older packets and owns idle freshness; `now` expires old owners.
    pub fn admit(&mut self, admission: Admission<'_>) -> Result<BindingLease, FirewallError> {
        let Admission {
            ingress,
            reply_ingress,
            facts,
            dnat,
            snat,
            egress,
            received_at,
            now,
        } = admission;
        self.expire(now);
        if received_at > now {
            return Err(FirewallError::Denied);
        }
        if ingress.scope != reply_ingress.scope
            || ingress.namespace == 0
            || ingress.namespace != reply_ingress.namespace
            || ingress.ifindex == 0
            || reply_ingress.ifindex == 0
            || ingress.attachment == 0
            || reply_ingress.attachment == 0
            || matches!(ingress.mark, crate::forward::MarkProvenance::Unavailable)
            || matches!(
                reply_ingress.mark,
                crate::forward::MarkProvenance::Unavailable
            )
        {
            return Err(FirewallError::Denied);
        }
        if self.epoch == 0 || facts.quote.is_some() || facts.echo_reply {
            return Err(FirewallError::Denied);
        }
        let state = if let Some(tcp) = facts.tcp {
            if tcp.flags & (tcp::SYN | tcp::ACK | tcp::RST | tcp::FIN) != tcp::SYN {
                return Err(FirewallError::Denied);
            }
            State::Opening {
                syn: [
                    Some(SynProof {
                        sequence: tcp.seq,
                        end: tcp
                            .seq
                            .wrapping_add(1)
                            .wrapping_add(facts.payload_len as u32),
                        bare: true,
                        with_ack: false,
                    }),
                    None,
                ],
                acknowledged: [false; 2],
            }
        } else {
            State::Datagram
        };
        if self.entries.len() == self.capacity {
            return Err(FirewallError::Capacity);
        }
        let original = facts.tuple;
        let destination = destination_tuple(original, dnat)?;
        let (address, pool, masquerade) = match snat {
            SourceNat::None => (None, None, None),
            SourceNat::Snat { address, ports } => (Some(address), ports, None),
            SourceNat::Masquerade { ports } => {
                let egress = egress
                    .filter(|value| value.ifindex == reply_ingress.ifindex && value.generation != 0)
                    .ok_or(FirewallError::AddressUnavailable)?;
                (Some(egress.address), Some(ports), Some(egress))
            }
        };
        if address.is_some() && !original.source.is_ipv4() {
            return Err(FirewallError::Unsupported);
        }
        if let Some(address) = address
            && !valid_address(address)
        {
            return Err(FirewallError::AddressUnavailable);
        }
        if pool.is_some_and(|pool| pool.first == 0 || pool.first > pool.last) {
            return Err(FirewallError::Unsupported);
        }
        let mut translated = destination;
        if let Some(address) = address {
            translated.source = IpAddr::V4(address);
        }
        let conflicts = |identity: Ingress, tuple: Tuple| {
            self.entries
                .iter()
                .any(|entry| entry.binding.aliases().contains(&(identity, tuple)))
        };
        if conflicts(ingress, original)
            || conflicts(ingress, original.reverse())
            || conflicts(ingress, destination)
            || conflicts(ingress, destination.reverse())
        {
            return Err(FirewallError::Conflict);
        }
        if original == original.reverse() {
            return Err(FirewallError::Conflict);
        }
        if let Some(pool) = pool {
            let available = (pool.first..=pool.last)
                .find(|port| {
                    let candidate = with_source_port(translated, *port);
                    candidate.reverse() != original
                        && candidate.reverse() != destination
                        && !conflicts(reply_ingress, candidate)
                        && !conflicts(reply_ingress, candidate.reverse())
                        && !self.port_owned(ingress, candidate)
                })
                .ok_or(FirewallError::Exhausted)?;
            translated = with_source_port(translated, available);
        } else if original == translated.reverse()
            || destination == translated.reverse()
            || conflicts(reply_ingress, translated)
            || conflicts(reply_ingress, translated.reverse())
            || (address.is_some() && self.port_owned(ingress, translated))
        {
            return Err(FirewallError::Conflict);
        }
        self.ensure_state()?;
        let charge = self
            .budget
            .reserve(size_of::<Binding>() + 2 * size_of::<usize>())
            .ok_or(FirewallError::Capacity)?;
        let binding = Arc::new(Binding {
            ingress,
            reply_ingress,
            original,
            destination,
            translated,
            epoch: self.epoch,
            masquerade,
            active: AtomicBool::new(true),
            fragment_pending: AtomicBool::new(false),
            _charge: charge,
        });
        let lease = self.lease(Arc::clone(&binding), Direction::Original, facts, None)?;
        self.entries.push(Entry {
            binding: Arc::clone(&binding),
            state,
            received_at,
            last: received_at,
        });
        Ok(lease)
    }
    fn lease(
        &mut self,
        binding: Arc<Binding>,
        direction: Direction,
        facts: &Facts,
        quoted_identity: Option<Arc<DatagramIdentity>>,
    ) -> Result<BindingLease, FirewallError> {
        let mut lease = BindingLease {
            binding,
            direction,
            identity: None,
            quoted_identity,
            _native_identity: None,
            authorized: true,
        };
        let Some(ipv4) = facts.ipv4.filter(|ipv4| ipv4.fragmentable) else {
            return Ok(lease);
        };
        let output = lease.after_route();
        let ingress = match direction {
            Direction::Original => lease.binding.ingress,
            Direction::Reply => lease.binding.reply_ingress,
            Direction::Related {
                quoted_reply: true, ..
            } => lease.binding.ingress,
            Direction::Related {
                quoted_reply: false,
                ..
            } => lease.binding.reply_ingress,
        };
        let translated = lease.binding.original != lease.binding.translated
            || self.identities.iter().any(|entry| {
                entry.identity.domain.matches(ingress, output)
                    && entry.identity.output_id == ipv4.id
            });
        if !translated {
            lease._native_identity =
                Some(self.native_lease(ingress, lease.egress_ingress(), output, ipv4.id)?);
            return Ok(lease);
        }
        let identity = self.allocate_identity(
            ingress,
            lease.egress_ingress(),
            output,
            ipv4.id,
            Some(Arc::clone(&lease.binding)),
            match direction {
                Direction::Original => Some(false),
                Direction::Reply => Some(true),
                Direction::Related { .. } => None,
            },
        )?;
        lease.identity = Some(identity);
        Ok(lease)
    }
    fn allocate_identity(
        &mut self,
        ingress: Ingress,
        egress: Ingress,
        output: Tuple,
        input_id: u16,
        binding: Option<Arc<Binding>>,
        reply: Option<bool>,
    ) -> Result<Arc<DatagramIdentity>, FirewallError> {
        self.ensure_state()?;
        if self.identities.len() == self.identity_capacity {
            return Err(FirewallError::Exhausted);
        }
        let mut native_history = false;
        for entry in &self.native_history {
            if entry.identity.domain.matches(ingress, output) {
                if !native_history {
                    self.native_bits.fill(0);
                    native_history = true;
                }
                let id = usize::from(entry.identity.id);
                self.native_bits[id / 64] |= 1u64 << (id % 64);
            }
        }
        let occupied = |word: usize| {
            self.id_bits[word]
                | self.overflow_bits[word]
                | if native_history {
                    self.native_bits[word]
                } else {
                    0
                }
        };
        let word = (0..IPV4_ID_WORDS)
            .map(|offset| (self.next_id_word + offset) % IPV4_ID_WORDS)
            .find(|word| occupied(*word) != u64::MAX)
            .ok_or(FirewallError::Exhausted)?;
        let bit = (!occupied(word)).trailing_zeros() as usize;
        let charge = self
            .budget
            .reserve(size_of::<DatagramIdentity>() + 2 * size_of::<usize>())
            .ok_or(FirewallError::Capacity)?;
        let identity = Arc::new(DatagramIdentity {
            binding,
            domain: WireDomain { ingress, output },
            quote_ingress: egress,
            reply,
            input_id,
            output_id: (word * 64 + bit) as u16,
            _charge: charge,
        });
        self.id_bits[word] |= 1u64 << bit;
        self.next_id_word = word;
        self.identities.push(IdentityEntry {
            identity: Arc::clone(&identity),
            retired_at: None,
            fragment_pending: false,
        });
        Ok(identity)
    }
    // ponytail: at most min(64*capacity,65536) exact rows; index after profiling.
    fn native_lease(
        &mut self,
        ingress: Ingress,
        egress: Ingress,
        output: Tuple,
        id: u16,
    ) -> Result<NativeLease, FirewallError> {
        if let Some(entry) = self.native_history.iter_mut().find(|entry| {
            entry.identity.id == id
                && entry.identity.quote_ingress == egress
                && entry.identity.domain.matches(ingress, output)
        }) {
            entry.retired_at = None;
            return Ok(NativeLease {
                retained: NativeRetention::Exact(Arc::clone(&entry.identity)),
            });
        }
        if self.native_history.len() < self.identity_capacity
            && let Some(charge) = self
                .budget
                .reserve(size_of::<NativeIdentity>() + 2 * size_of::<usize>())
        {
            let identity = Arc::new(NativeIdentity {
                domain: WireDomain { ingress, output },
                quote_ingress: egress,
                id,
                _charge: charge,
            });
            self.native_history.push(NativeEntry {
                identity: Arc::clone(&identity),
                retired_at: None,
                fragment_pending: false,
            });
            return Ok(NativeLease {
                retained: NativeRetention::Exact(identity),
            });
        }
        let index = usize::from(id);
        self.native_overflow.counts[index]
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| FirewallError::Capacity)?;
        if self.overflow_bits[index / 64] & (1u64 << (index % 64)) == 0 {
            self.overflow_active += 1;
        }
        self.overflow_bits[index / 64] |= 1u64 << (index % 64);
        self.native_overflow.retired[index].store(0, Ordering::Release);
        Ok(NativeLease {
            retained: NativeRetention::Overflow(OverflowLease {
                owner: Arc::clone(&self.native_overflow),
                id,
            }),
        })
    }
    /// Observe an allowed DF-clear output; this creates no conntrack state or admission.
    pub fn observe_plain(
        &mut self,
        ingress: Ingress,
        egress: Ingress,
        output: Tuple,
        id: u16,
        now: Instant,
    ) -> Result<NativeLease, FirewallError> {
        self.expire(now);
        if !output.source.is_ipv4() || !output.destination.is_ipv4() {
            return Err(FirewallError::Unsupported);
        }
        if self.identities.iter().any(|entry| {
            entry.identity.domain.matches(ingress, output) && entry.identity.output_id == id
        }) {
            let identity = self.allocate_identity(ingress, egress, output, id, None, None)?;
            Ok(NativeLease {
                retained: NativeRetention::Remapped(identity),
            })
        } else {
            self.native_lease(ingress, egress, output, id)
        }
    }
    /// A minimum or non-first quote can retain an unbound ID repair, never a flow grant.
    pub fn retain_native_quote(&self, ingress: Ingress, facts: &Facts) -> Option<NativeQuoteLease> {
        let quote = facts.quote?;
        let ipv4 = quote
            .ipv4
            .filter(|ipv4| ipv4.fragmentable || quote.nonfirst)?;
        if let Some(identity) = self.identities.iter().find_map(|entry| {
            let identity = &entry.identity;
            (identity.binding.is_none()
                && identity.quote_ingress == ingress
                && ipv4.id == identity.output_id
                && quote.matches(identity.domain.output)
                && facts.tuple.destination == identity.domain.output.source)
                .then(|| Arc::clone(identity))
        }) {
            return Some(NativeQuoteLease {
                identity: Some(identity),
                _overflow: None,
            });
        }
        let index = usize::from(ipv4.id);
        if self.overflow_bits[index / 64] & (1u64 << (index % 64)) == 0 {
            return None;
        }
        self.native_overflow.counts[index]
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .ok()?;
        self.native_overflow.retired[index].store(0, Ordering::Release);
        Some(NativeQuoteLease {
            identity: None,
            _overflow: Some(OverflowLease {
                owner: Arc::clone(&self.native_overflow),
                id: ipv4.id,
            }),
        })
    }
    fn port_owned(&self, ingress: Ingress, tuple: Tuple) -> bool {
        // ponytail: bounded 4096-entry linear scan; index only after profiling the slow owner.
        self.entries.iter().any(|entry| {
            entry.binding.domain(ingress)
                && entry.binding.translated.protocol == tuple.protocol
                && entry.binding.translated.source == tuple.source
                && entry.binding.translated.source_port == tuple.source_port
        })
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        for entry in &self.entries {
            entry.binding.active.store(false, Ordering::Release);
        }
    }
}

fn rewrite_id(bytes: &mut [u8], id: u16) -> Result<(), FirewallError> {
    let ip = wire::parse_ip(bytes)?;
    if !ip.src.is_ipv4() {
        return Err(FirewallError::Unsupported);
    }
    if bytes[4..6] == id.to_be_bytes() {
        return Ok(());
    }
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[10..12].fill(0);
    let checksum = wire::checksum::checksum(&bytes[..ip.payload.start]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn with_source_port(mut tuple: Tuple, port: u16) -> Tuple {
    tuple.source_port = port;
    if tuple.protocol == wire::PROTO_ICMP {
        tuple.destination_port = port;
    }
    tuple
}
fn transition(state: State, facts: &Facts, reply: bool) -> Result<State, FirewallError> {
    let Some(header) = facts.tcp else {
        if facts.tuple.protocol != wire::PROTO_UDP && facts.echo_reply != reply {
            return Err(FirewallError::Denied);
        }
        return Ok(state);
    };
    let flags = header.flags & (tcp::SYN | tcp::ACK | tcp::RST | tcp::FIN);
    match state {
        State::Opening {
            mut syn,
            mut acknowledged,
        } => {
            let side = usize::from(reply);
            let peer = 1 - side;
            if flags & tcp::RST != 0 {
                let valid = if flags == (tcp::RST | tcp::ACK) {
                    syn[peer].is_some_and(|proof| proof.acknowledges(header.ack))
                } else {
                    flags == tcp::RST
                        && syn[side].is_some_and(|proof| proof.acknowledges(header.seq))
                };
                return if valid {
                    Ok(State::Closing)
                } else {
                    Err(FirewallError::Denied)
                };
            }
            if flags & tcp::SYN != 0 {
                if flags & tcp::FIN != 0 {
                    return Err(FirewallError::Denied);
                }
                let proof = SynProof {
                    sequence: header.seq,
                    end: header
                        .seq
                        .wrapping_add(1)
                        .wrapping_add(facts.payload_len as u32),
                    bare: flags & tcp::ACK == 0,
                    with_ack: flags & tcp::ACK != 0,
                };
                if let Some(previous) = &mut syn[side] {
                    if !previous.matches(header.seq, facts.payload_len) {
                        return Err(FirewallError::Denied);
                    }
                    previous.bare |= proof.bare;
                    previous.with_ack |= proof.with_ack;
                } else {
                    syn[side] = Some(proof);
                }
                if flags & tcp::ACK != 0 {
                    if !syn[peer].is_some_and(|proof| proof.acknowledges(header.ack)) {
                        return Err(FirewallError::Denied);
                    }
                    acknowledged[peer] = true;
                }
                return Ok(State::Opening { syn, acknowledged });
            }
            if flags & tcp::ACK == 0
                || !syn[side].is_some_and(|proof| proof.acknowledges(header.seq))
                || !syn[peer].is_some_and(|proof| proof.acknowledges(header.ack))
            {
                return Err(FirewallError::Denied);
            }
            acknowledged[peer] = true;
            if !acknowledged.into_iter().all(|value| value) {
                return Err(FirewallError::Denied);
            }
            Ok(if flags & tcp::FIN != 0 {
                State::Closing
            } else {
                State::Established { syn }
            })
        }
        State::Established { syn } if flags & tcp::SYN != 0 => {
            let side = usize::from(reply);
            let peer = 1 - side;
            let valid = syn[side].is_some_and(|proof| {
                proof.matches(header.seq, facts.payload_len)
                    && if flags == tcp::SYN {
                        proof.bare
                    } else {
                        flags == (tcp::SYN | tcp::ACK)
                            && proof.with_ack
                            && syn[peer].is_some_and(|proof| proof.acknowledges(header.ack))
                    }
            });
            if valid {
                Ok(state)
            } else {
                Err(FirewallError::Denied)
            }
        }
        // Without receive-window authority, FIN/RST cannot shorten established protection.
        State::Established { .. } | State::Closing if header.flags & tcp::SYN == 0 => Ok(state),
        _ => Err(FirewallError::Denied),
    }
}
fn valid_address(ip: Ipv4Addr) -> bool {
    honk_netstack::transit::unicast(IpAddr::V4(ip))
}

pub fn destination_tuple(
    mut original: Tuple,
    action: Option<DestinationNat>,
) -> Result<Tuple, FirewallError> {
    if let Some(action) = action {
        if !original.destination.is_ipv4()
            || !valid_address(action.address)
            || action.port == Some(0)
        {
            return Err(FirewallError::Unsupported);
        }
        if action.port.is_some() && !matches!(original.protocol, wire::PROTO_TCP | wire::PROTO_UDP)
        {
            return Err(FirewallError::Unsupported);
        }
        original.destination = IpAddr::V4(action.address);
        if let Some(port) = action.port {
            original.destination_port = port;
        }
    }
    Ok(original)
}

fn rewrite_tuple(
    bytes: &mut [u8],
    target: Tuple,
    ipv4_id: Option<u16>,
) -> Result<(), FirewallError> {
    let ip = wire::parse_ip(bytes)?;
    if ip.src.is_ipv6() {
        if ip.src != target.source || ip.dst != target.destination {
            return Err(FirewallError::Unsupported);
        }
        return Ok(());
    }
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (target.source, target.destination) else {
        return Err(FirewallError::Unsupported);
    };
    if target.protocol != ip.proto {
        return Err(FirewallError::Unsupported);
    }
    let offset = ip.payload.start;
    let end = ip.payload.end;
    let minimum = match ip.proto {
        wire::PROTO_TCP => 20,
        wire::PROTO_UDP | wire::PROTO_ICMP => 8,
        _ => return Err(FirewallError::Unsupported),
    };
    if end - offset < minimum {
        return Err(ParseError::Malformed.into());
    }
    let end = if ip.proto == wire::PROTO_UDP {
        offset + wire::udp::parse(&bytes[offset..end])?.2.end
    } else {
        end
    };
    if let Some(id) = ipv4_id {
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
    }
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[10..12].fill(0);
    let checksum = wire::checksum::checksum(&bytes[..offset]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    let segment = &mut bytes[offset..end];
    match ip.proto {
        wire::PROTO_TCP | wire::PROTO_UDP => {
            let field = if ip.proto == wire::PROTO_TCP { 16 } else { 6 };
            let udp_zero = ip.proto == wire::PROTO_UDP && segment[field..field + 2] == [0, 0];
            segment[..2].copy_from_slice(&target.source_port.to_be_bytes());
            segment[2..4].copy_from_slice(&target.destination_port.to_be_bytes());
            segment[field..field + 2].fill(0);
            if !udp_zero {
                let mut checksum =
                    Checksum::pseudo(target.source, target.destination, ip.proto, segment.len());
                checksum.add(segment);
                let value = checksum.finish();
                segment[field..field + 2].copy_from_slice(
                    &(if value == 0 && ip.proto == wire::PROTO_UDP {
                        u16::MAX
                    } else {
                        value
                    })
                    .to_be_bytes(),
                );
            }
        }
        wire::PROTO_ICMP => {
            if matches!(segment[0], 0 | 8) {
                segment[4..6].copy_from_slice(&target.source_port.to_be_bytes());
            }
            segment[2..4].fill(0);
            let value = wire::checksum::checksum(segment);
            segment[2..4].copy_from_slice(&value.to_be_bytes());
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn icmp_quote_end(segment: &[u8]) -> Result<usize, FirewallError> {
    if segment.len() < 8 {
        return Err(ParseError::Malformed.into());
    }
    // RFC 4884's nonzero IPv4 original-datagram length excludes extension objects.
    let end = if segment[5] == 0 {
        segment.len()
    } else {
        8 + usize::from(segment[5]) * 4
    };
    if end > segment.len() {
        return Err(ParseError::Malformed.into());
    }
    Ok(end)
}

fn quoted_tuple(bytes: &[u8]) -> Result<Tuple, FirewallError> {
    let (header, protocol) = match bytes.first().map(|byte| byte >> 4) {
        Some(4) => {
            if bytes.len() < 20 {
                return Err(ParseError::Malformed.into());
            }
            let header = usize::from(bytes[0] & 15) * 4;
            if header < 20
                || bytes.len() < header + 8
                || (u16::from_be_bytes([bytes[2], bytes[3]]) as usize) < header + 8
                || wire::checksum::checksum(&bytes[..header]) != 0
            {
                return Err(ParseError::Malformed.into());
            }
            if u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff != 0 {
                if !matches!(
                    bytes[9],
                    wire::PROTO_TCP | wire::PROTO_UDP | wire::PROTO_ICMP
                ) {
                    return Err(FirewallError::Unsupported);
                }
                return Ok(Tuple {
                    source: IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(&bytes[12..16]).unwrap(),
                    )),
                    destination: IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(&bytes[16..20]).unwrap(),
                    )),
                    protocol: bytes[9],
                    source_port: 0,
                    destination_port: 0,
                });
            }
            (header, bytes[9])
        }
        Some(6) => {
            if bytes.len() < 48 || u16::from_be_bytes([bytes[4], bytes[5]]) < 8 {
                return Err(ParseError::Malformed.into());
            }
            (40, bytes[6])
        }
        _ => return Err(FirewallError::Unsupported),
    };
    if matches!(protocol, wire::PROTO_TCP | wire::PROTO_UDP) {
        let quote = wire::icmp::parse_quoted(bytes).ok_or(FirewallError::Unsupported)?;
        return Ok(Tuple {
            source: quote.src,
            destination: quote.dst,
            protocol: quote.proto,
            source_port: quote.src_port,
            destination_port: quote.dst_port,
        });
    }
    let segment = &bytes[header..];
    if !matches!(
        (protocol, segment[0]),
        (wire::PROTO_ICMP, 0 | 8) | (wire::PROTO_ICMPV6, 128 | 129)
    ) {
        return Err(FirewallError::Unsupported);
    }
    let quote = honk_netstack::transit::quote_metadata(bytes).ok_or(FirewallError::Unsupported)?;
    let id = u16::from_be_bytes([segment[4], segment[5]]);
    Ok(Tuple {
        source: quote.source,
        destination: quote.destination,
        protocol,
        source_port: id,
        destination_port: id,
    })
}
fn repair_icmp_quote(
    bytes: &mut [u8],
    expected: Tuple,
    restored: Tuple,
    identity: Option<(u16, u16)>,
) -> Result<(), FirewallError> {
    let ip = wire::parse_ip(bytes)?;
    if ip.proto != wire::PROTO_ICMP || ip.payload.len() < 8 {
        return Err(FirewallError::Unsupported);
    }
    let end = ip.payload.start + icmp_quote_end(&bytes[ip.payload.clone()])?;
    let quote = &mut bytes[ip.payload.start + 8..end];
    let actual = Quote::parse(quote)?;
    if actual.matches(restored)
        && identity.is_none_or(|(_, id)| actual.ipv4.is_some_and(|ipv4| ipv4.id == id))
    {
        return Ok(());
    }
    if !actual.matches(expected)
        || identity.is_some_and(|(id, _)| actual.ipv4.is_none_or(|ipv4| ipv4.id != id))
    {
        return Err(FirewallError::Conflict);
    }
    let header = usize::from(quote[0] & 15) * 4;
    let (IpAddr::V4(source), IpAddr::V4(destination)) = (restored.source, restored.destination)
    else {
        return Err(FirewallError::Unsupported);
    };
    let old_addresses: [u8; 8] = quote[12..20].try_into().unwrap();
    let mut new_addresses = [0; 8];
    new_addresses[..4].copy_from_slice(&source.octets());
    new_addresses[4..].copy_from_slice(&destination.octets());
    if !actual.nonfirst {
        let inner_end = quote
            .len()
            .min(usize::from(u16::from_be_bytes([quote[2], quote[3]])));
        let segment = &mut quote[header..inner_end];
        let field = match actual.tuple.protocol {
            wire::PROTO_TCP => 16,
            wire::PROTO_UDP => 6,
            wire::PROTO_ICMP => 2,
            _ => return Err(FirewallError::Unsupported),
        };
        let old_ports: [u8; 4] = segment[..4].try_into().unwrap();
        let mut new_ports = [0; 4];
        new_ports[..2].copy_from_slice(&restored.source_port.to_be_bytes());
        new_ports[2..].copy_from_slice(&restored.destination_port.to_be_bytes());
        if actual.tuple.protocol == wire::PROTO_ICMP {
            let old = [segment[4], segment[5]];
            let new = restored.source_port.to_be_bytes();
            let checksum = adjust(u16::from_be_bytes([segment[2], segment[3]]), &old, &new);
            segment[2..4].copy_from_slice(&checksum.to_be_bytes());
            segment[4..6].copy_from_slice(&new);
        } else {
            // A minimum TCP quote has no checksum; a present zero UDP checksum stays zero.
            if segment.len() >= field + 2 {
                let previous = u16::from_be_bytes([segment[field], segment[field + 1]]);
                if actual.tuple.protocol != wire::PROTO_UDP || previous != 0 {
                    let changed = adjust(
                        adjust(previous, &old_addresses, &new_addresses),
                        &old_ports,
                        &new_ports,
                    );
                    let changed = if actual.tuple.protocol == wire::PROTO_UDP && changed == 0 {
                        u16::MAX
                    } else {
                        changed
                    };
                    segment[field..field + 2].copy_from_slice(&changed.to_be_bytes());
                }
            }
            segment[..4].copy_from_slice(&new_ports);
        }
    }
    quote[12..20].copy_from_slice(&new_addresses);
    if let Some((_, id)) = identity {
        quote[4..6].copy_from_slice(&id.to_be_bytes());
    }
    quote[10..12].fill(0);
    let checksum = wire::checksum::checksum(&quote[..header]);
    quote[10..12].copy_from_slice(&checksum.to_be_bytes());
    // Outer checksum is sealed by rewrite_tuple after the quote and outer IP change.
    Ok(())
}
fn adjust(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = Checksum::new();
    sum.add_u16(!checksum);
    for pair in old.as_chunks::<2>().0 {
        sum.add_u16(!u16::from_be_bytes(*pair));
    }
    sum.add(new);
    match sum.finish() {
        // An all-zero echo reply requires negative zero; either zero works otherwise.
        0 => u16::MAX,
        checksum => checksum,
    }
}

#[cfg(test)]
mod tests;
