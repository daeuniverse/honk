//! Reassembly and ICMP facilities for IP transit, without transport termination.
//!
//! One instance belongs to one ingress identity (namespace, logical input interface and
//! attachment incarnation). Callers must share one budget across all such instances.

use std::{net::IpAddr, sync::Arc, time::Instant};

pub use crate::fragment::Ipv6Fragment;

use crate::{
    DropReason, FragmentLimits, IcmpLimits, MemoryBudget, MemoryReservation, OwnedPacket,
    fragment::{Push, Reassembler},
    icmp_out::{IcmpEmit, IcmpOut, Reject},
    wire::{self, ParseError},
};

/// Metadata actually retained from fragment zero, not a validated complete transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub traffic_class: u8,
    pub ports: Option<(u16, u16)>,
    pub header_len: usize,
}

/// Reuses the error generator's truncated/first-fragment decoder and suppression rules.
/// Missing TCP reset flags are not assumed clear.
pub fn quote_metadata(packet: &[u8]) -> Option<Quote> {
    crate::icmp_out::quote_metadata(packet)
}

/// Errors a router may originate; port refusal remains an Endpoint operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitError {
    HopLimitExceeded,
    ReassemblyTimeExceeded,
    HostUnreachable,
    AdminProhibited,
    PacketTooBig { mtu: u32 },
}

/// A packet-local refusal never authorizes native continuation.
pub struct Transit {
    fragments: Reassembler,
    icmp: IcmpOut,
    _metadata: MemoryReservation,
}

impl Transit {
    pub fn new(budget: Arc<MemoryBudget>, limits: FragmentLimits) -> Option<Self> {
        let icmp_limits = IcmpLimits::default();
        let bytes = Reassembler::overhead_bound(limits)?
            .checked_add(Reassembler::scratch_bound(limits)?)?
            .checked_add(IcmpOut::overhead_bound(icmp_limits)?)?
            .checked_add(size_of::<Self>())?;
        let metadata = budget.reserve(bytes)?;
        Some(Self {
            fragments: Reassembler::new(limits)
                .for_transit()
                .with_budget(Some(budget)),
            icmp: IcmpOut::new(icmp_limits),
            _metadata: metadata,
        })
    }

    /// Only fragmented inputs enter storage. A completed packet still requires full
    /// IP/transport validation by the caller before publishing flow or route state.
    /// Expired assemblies cannot complete even when the caller's timer polling is delayed.
    pub fn reassemble(
        &mut self,
        now: Instant,
        packet: &[u8],
    ) -> Result<Option<OwnedPacket>, DropReason> {
        let fragment = wire::frag::parse(packet).map_err(DropReason::from)?;
        for address in [fragment.src, fragment.dst] {
            if !unicast(address) {
                return Err(DropReason::Unsupported);
            }
        }
        self.fragments.expire(now);
        match self.fragments.push(now, fragment) {
            Push::Pending => Ok(None),
            Push::Complete(complete) => Ok(Some(complete.packet)),
            Push::Dropped(reason) => Err(reason),
        }
    }

    pub fn expire(&mut self, now: Instant) {
        self.fragments.expire(now);
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.fragments.poll_timeout()
    }

    pub fn is_quiescent(&self) -> bool {
        self.fragments.is_quiescent()
    }

    /// Address/protocol domains still needed by live reassemblies or queued timeout quotes.
    /// Tombstones cannot complete or originate a quote and retain no translation authority.
    pub fn fragment_obligations(&self) -> impl Iterator<Item = (IpAddr, IpAddr, u8)> + Clone + '_ {
        self.fragments.obligations()
    }

    pub fn poll_expired_quote(&mut self) -> Option<OwnedPacket> {
        self.fragments.take_expired()
    }

    /// `source` is a local router address selected by the adapter, never the remote
    /// destination impersonated by Endpoint ICMP. `None` means suppressed/rate-limited.
    pub fn error(
        &mut self,
        now: Instant,
        error: TransitError,
        source: IpAddr,
        original: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, ParseError> {
        let version = original.first().ok_or(ParseError::Malformed)? >> 4;
        if !matches!(version, 4 | 6) || !unicast(source) || source.is_ipv4() != (version == 4) {
            return Err(ParseError::Unsupported);
        }
        let kind = match error {
            TransitError::HopLimitExceeded => Reject::HopLimitExceeded,
            TransitError::ReassemblyTimeExceeded => Reject::TimeExceeded,
            TransitError::HostUnreachable => Reject::HostUnreachable,
            TransitError::AdminProhibited => Reject::AdminProhibited,
            TransitError::PacketTooBig { mtu } => Reject::PacketTooBig { mtu },
        };
        match self.icmp.emit_from(now, kind, original, Some(source), out) {
            IcmpEmit::Sent(n) => Ok(Some(n)),
            IcmpEmit::Suppressed | IcmpEmit::RateLimited => Ok(None),
            IcmpEmit::TooSmall => Err(ParseError::Malformed),
        }
    }
}

/// Reject special and IPv4-mapped wire addresses before fragment ownership is mutated.
pub fn unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_loopback()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 240
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}
