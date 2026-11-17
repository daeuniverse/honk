//! Read-only admission for preprovisioned own-socket uplink routing.
//!
//! A dedicated exact-bypass-mark RPDB table isolates socket output from captured
//! ports without replacing CoreForward's input FIB. Native replacements retain
//! this authority by accounting for one exact link event under the mutation lock.
//! Other notifications remain sticky; RTNL observation is not an external-write fence.
//! Kernel IPv6 ff00::/8 multicast routes remain outside native unicast capture.
//!
//! TUN admission instead proves only what the daemon created: one link, its exact
//! addresses, the five per-family rules at `[P, P+4]` and the dedicated capture table,
//! beside operator main routing it can represent completely. Unknown selectors, actions,
//! nexthop forms and attributes are refused rather than interpreted.

use std::collections::HashSet;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use honk_netstack::{MemoryBudget, MemoryReservation};

use crate::bpf::{attributes, wait_netlink};

const MAX_OBJECTS: usize = 65_536;
pub(crate) const MAX_BROADCASTS: usize = 64;

const IFA_F_NODAD: u32 = 0x02;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;
const FIB_RULE_IIF_DETACHED: u32 = 0x08;
const RTNH_F_LINKDOWN: u32 = 0x10;
const FR_ACT_PROHIBIT: u8 = 8;
const RTN_BLACKHOLE: u8 = 6;
const RTPROT_STATIC: u8 = 4;
const TUN_GUARD_METRIC: u32 = 32760;
// IPv6 stores metric 0 as 1024, and IPv4 deletion treats priority 0 as a wildcard.
const TUN_CAPTURE_METRIC: u32 = 1024;

/// Borrowed TUN configuration plus the process bypass mark capture must route around.
#[derive(Clone, Copy, Debug)]
pub struct TunSpec<'a> {
    pub name: &'a str,
    pub mtu: u32,
    pub address4: Option<Ipv4Addr>,
    pub address6: Option<Ipv6Addr>,
    pub table: u32,
    pub rule_priority: u32,
    pub bypass_mark: u32,
    pub capture: &'a [(IpAddr, u8)],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunRouteKind {
    Blackhole,
    Unicast { oif: u32 },
}

/// One bare `RTPROT_STATIC` route in the dedicated capture table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunRoute {
    pub table: u32,
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub kind: TunRouteKind,
    pub metric: u32,
}

/// `Fwmark` carries an exact `0xffffffff` mask; `Iif` names the owned TUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunRuleSelector {
    Fwmark(u32),
    Iif,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunRuleAction {
    Lookup(u32),
    Prohibit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunRule {
    pub ipv6: bool,
    pub priority: u32,
    pub selector: TunRuleSelector,
    pub action: TunRuleAction,
}

/// `Guarded` holds every rule and blackhole guard but no capture route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunStage {
    Guarded,
    Active,
}

/// Cleanup facts from one dump; `None` marks an object no TUN key represents exactly.
#[derive(Debug)]
pub struct TunReadback {
    /// Some link, of any identity, still has the recorded ifindex.
    pub link: bool,
    pub addresses: Vec<(IpAddr, u8)>,
    /// Every capture-table route as `(table, destination, prefix, metric, key)`.
    pub routes: Vec<(u32, IpAddr, u8, u32, Option<TunRoute>)>,
    /// Every rule of either family in `[P, P+4]` as `(ipv6, priority, key)`.
    pub rules: Vec<(bool, u32, Option<TunRule>)>,
}

impl TunSpec<'_> {
    /// Per enabled family, IPv4 first, in install order `P..=P+4`.
    pub fn rules(&self) -> Vec<TunRule> {
        use TunRuleAction::{Lookup, Prohibit};
        use TunRuleSelector::{All, Fwmark, Iif};
        let mark = Fwmark(self.bypass_mark);
        let shape = [
            (mark, Lookup(254)),
            (mark, Prohibit),
            (Iif, Lookup(254)),
            (Iif, Prohibit),
            (All, Lookup(self.table)),
        ];
        let mut rules = Vec::with_capacity(2 * shape.len());
        for ipv6 in self.families() {
            for (offset, (selector, action)) in (0..).zip(shape) {
                rules.push(TunRule {
                    ipv6,
                    priority: self.rule_priority.saturating_add(offset),
                    selector,
                    action,
                });
            }
        }
        rules
    }

    pub fn guard_routes(&self) -> Vec<TunRoute> {
        self.routes(TunRouteKind::Blackhole, TUN_GUARD_METRIC)
    }

    pub fn capture_routes(&self, oif: u32) -> Vec<TunRoute> {
        self.routes(TunRouteKind::Unicast { oif }, TUN_CAPTURE_METRIC)
    }

    fn routes(&self, kind: TunRouteKind, metric: u32) -> Vec<TunRoute> {
        self.capture
            .iter()
            .map(|&(destination, prefix_len)| TunRoute {
                table: self.table,
                destination,
                prefix_len,
                kind,
                metric,
            })
            .collect()
    }

    fn families(&self) -> impl Iterator<Item = bool> {
        [self.address4.map(|_| false), self.address6.map(|_| true)]
            .into_iter()
            .flatten()
    }

    fn addresses(&self) -> impl Iterator<Item = IpAddr> {
        [self.address4.map(IpAddr::V4), self.address6.map(IpAddr::V6)]
            .into_iter()
            .flatten()
    }

    /// Refuses values that would make derived keys or the reserved range inexact.
    fn validate(&self) -> io::Result<[u8; 16]> {
        let name = self.name.as_bytes();
        let network = |&(destination, prefix): &(IpAddr, u8)| match destination {
            IpAddr::V4(ip) => self.address4.is_some() && network_address(IpAddr::V4(ip), prefix),
            IpAddr::V6(ip) => self.address6.is_some() && network_address(IpAddr::V6(ip), prefix),
        };
        if name.is_empty()
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
            || matches!(self.name, "lo" | "auto")
            || !(1280..=65535).contains(&self.mtu)
            || self.address4.is_some_and(|ip| {
                ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_link_local()
            })
            || self.address6.is_some_and(|ip| {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unicast_link_local()
                    || ip.to_ipv4_mapped().is_some()
            })
            || (self.address4.is_none() && self.address6.is_none())
            || self.bypass_mark == 0
            || self.bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
            || matches!(self.table, 0 | 253..=255 | u32::MAX)
            || self.rule_priority == 0
            || self
                .rule_priority
                .checked_add(4)
                .is_none_or(|last| last >= 32766)
            || self.capture.is_empty()
            || self.capture.len() > 64
            || !self.capture.iter().all(network)
            || self
                .capture
                .iter()
                .enumerate()
                .any(|(index, &(address, prefix))| {
                    self.capture[..index].iter().any(|&(other, other_prefix)| {
                        let common = prefix.min(other_prefix);
                        match (address, other) {
                            (IpAddr::V4(a), IpAddr::V4(b)) => {
                                u32::from(a)
                                    .checked_shr(u32::from(32 - common))
                                    .unwrap_or(0)
                                    == u32::from(b)
                                        .checked_shr(u32::from(32 - common))
                                        .unwrap_or(0)
                            }
                            (IpAddr::V6(a), IpAddr::V6(b)) => {
                                u128::from(a)
                                    .checked_shr(u32::from(128 - common))
                                    .unwrap_or(0)
                                    == u128::from(b)
                                        .checked_shr(u32::from(128 - common))
                                        .unwrap_or(0)
                            }
                            _ => false,
                        }
                    })
                })
        {
            return Err(unsupported(
                "invalid TUN name, addresses, mark, table, priority range or capture prefixes",
            ));
        }
        interface_name(name)
    }
}

pub struct Topology {
    fd: OwnedFd,
    watch: WatchState,
    ipv4_broadcasts: [Ipv4Addr; MAX_BROADCASTS],
    broadcast_count: usize,
}

enum WatchState {
    Strict { invalidated: bool },
    Native(NativeXdpUpdates),
}

/// Shares the retained subscription with the serialized Native mutation boundary.
#[derive(Clone)]
pub struct NativeXdpUpdates(Arc<Mutex<NativeWatch>>);

impl Topology {
    /// Requires operator-provisioned mark rules/tables; never writes host routes.
    /// Call before attaching capture, then retain and watch this descriptor for
    /// the whole attachment lifetime. Any invalidation requires closing admission.
    /// Physical roots and every canonical-FIB-proven VLAN descendant belong in
    /// `captured_logical`; discovering a sysfs upper never authorizes it here.
    pub fn admit(
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
    ) -> io::Result<Self> {
        Self::admit_until(captured_physical, captured_logical, bypass_mark, None)
    }

    /// Native drivers may renegotiate carrier after their first XDP attachment.
    pub fn admit_after_xdp_attach(
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
    ) -> io::Result<Self> {
        validate_capture_sets(captured_physical, captured_logical, bypass_mark)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let fd = route_socket(false)?;
        settle_xdp_carrier(
            deadline,
            |deadline| {
                let watch = route_socket(true)?;
                let current = snapshot(fd.as_fd(), Some(deadline))?;
                let pending = current
                    .pending_xdp_carrier(captured_physical, captured_logical, bypass_mark)?
                    .map(|link| PendingCarrier {
                        index: link.index,
                        name: link.name,
                    });
                Ok((watch, pending))
            },
            |watch: OwnedFd, deadline| wait_netlink(watch.as_fd(), libc::POLLIN, deadline),
            |deadline| {
                Self::admit_until(captured_physical, captured_logical, bypass_mark, deadline)
            },
            Instant::now,
        )
    }

    fn admit_until(
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
        deadline: Option<Instant>,
    ) -> io::Result<Self> {
        validate_capture_sets(captured_physical, captured_logical, bypass_mark)?;
        check_xdp_admission_deadline(deadline)?;
        let fd = route_socket(true)?;
        let dump_fd = deadline.map(|_| route_socket(false)).transpose()?;
        let snapshot = snapshot(dump_fd.as_ref().unwrap_or(&fd).as_fd(), deadline)?;
        snapshot.admit(captured_physical, captured_logical, bypass_mark)?;
        let (ipv4_broadcasts, broadcast_count) = snapshot.ipv4_broadcasts()?;
        let mut topology = Self {
            fd,
            watch: WatchState::Strict { invalidated: false },
            ipv4_broadcasts,
            broadcast_count,
        };
        if topology.check_changed()? {
            return Err(unsupported("routing topology changed during admission"));
        }
        check_xdp_admission_deadline(deadline)?;
        Ok(topology)
    }

    /// Before creating the TUN: subscribes, then proves the name, addresses, capture
    /// table and `[P, P+4]` are free and each enabled family has an operator uplink.
    pub fn preflight_tun(spec: &TunSpec<'_>) -> io::Result<Self> {
        Self::watch_tun(spec, None)
    }

    /// Completes only the owned IPv6 local-route work before any guards or rules
    /// divert traffic. Foreign topology and malformed observations stay terminal.
    pub fn wait_tun_device(spec: &TunSpec<'_>, ifindex: u32) -> io::Result<()> {
        let name = spec.validate()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let fd = route_socket(false)?;
        loop {
            let watch = route_socket(true)?;
            let ready =
                snapshot(fd.as_fd(), Some(deadline))?.tun_ready(spec, name, Some(ifindex), None)?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned TUN device readiness deadline expired",
                ));
            }
            if ready {
                return Ok(());
            }
            wait_netlink(watch.as_fd(), libc::POLLIN, deadline)?;
        }
    }

    /// Proves exactly the owned link, addresses, rules and guards (plus capture routes
    /// when `Active`) beside representable operator routing. Retain and watch it like
    /// [`Self::admit`]; any invalidation requires closing capture admission.
    pub fn admit_tun(spec: &TunSpec<'_>, ifindex: u32, stage: TunStage) -> io::Result<Self> {
        Self::watch_tun(spec, Some((ifindex, stage)))
    }

    fn watch_tun(spec: &TunSpec<'_>, owned: Option<(u32, TunStage)>) -> io::Result<Self> {
        let name = spec.validate()?;
        let fd = route_socket(true)?;
        snapshot(fd.as_fd(), None)?.admit_tun(spec, name, owned)?;
        let mut topology = Self {
            fd,
            watch: WatchState::Strict { invalidated: false },
            ipv4_broadcasts: [Ipv4Addr::UNSPECIFIED; MAX_BROADCASTS],
            broadcast_count: 0,
        };
        if topology.check_changed()? {
            return Err(unsupported("routing topology changed during admission"));
        }
        Ok(topology)
    }

    /// Exact local-table broadcast destinations from this watched namespace.
    pub fn ipv4_broadcasts(&self) -> &[Ipv4Addr] {
        &self.ipv4_broadcasts[..self.broadcast_count]
    }

    /// Sticky fail-closed invalidation, including receive loss and malformed
    /// notifications. No drain/re-admit loop can silently restore old authority.
    pub fn check_changed(&mut self) -> io::Result<bool> {
        let invalidated = match &mut self.watch {
            WatchState::Strict { invalidated } => invalidated,
            WatchState::Native(updates) => return updates.lock().check_changed(),
        };
        if *invalidated {
            return Ok(true);
        }
        let mut byte = [0u8; 1];
        loop {
            // SAFETY: byte is writable; MSG_TRUNC discards the entire datagram.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    byte.as_mut_ptr().cast(),
                    1,
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if n >= 0 {
                *invalidated = true;
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => return Ok(false),
                io::ErrorKind::Interrupted => continue,
                _ => {
                    *invalidated = true;
                    return Err(error);
                }
            }
        }
    }

    /// Only final Native startup admission may establish the shared authority.
    pub fn enable_native_xdp_updates(
        &mut self,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<NativeXdpUpdates> {
        if !matches!(self.watch, WatchState::Strict { invalidated: false })
            || self.check_changed()?
        {
            return Err(unsupported(
                "invalidated or already bound topology authority",
            ));
        }
        let reservation = budget
            .reserve(
                4 * NATIVE_LINK_CAPACITY
                    + 3 * size_of::<[u64; 256]>()
                    + size_of::<NativeWatch>()
                    + size_of::<Mutex<NativeWatch>>()
                    + 2 * size_of::<usize>()
                    + size_of::<OwnedFd>(),
            )
            .ok_or_else(|| io::Error::other("Native topology watch memory capacity"))?;
        let updates = NativeXdpUpdates(Arc::new(Mutex::new(NativeWatch {
            fd: self.fd.try_clone()?,
            invalidated: false,
            receive: vec![0; NATIVE_LINK_CAPACITY],
            baseline: Vec::with_capacity(NATIVE_LINK_CAPACITY),
            observed: Vec::with_capacity(NATIVE_LINK_CAPACITY),
            _reservation: reservation,
            #[cfg(test)]
            before_setter: None,
            #[cfg(test)]
            receive_hook: None,
            #[cfg(test)]
            consumed: 0,
        })));
        self.watch = WatchState::Native(updates.clone());
        Ok(updates)
    }
}

pub(crate) fn check_captured_return(
    tap: u32,
    targets: &[crate::bpf::CapturedTarget],
) -> io::Result<()> {
    let fd = route_socket(false)?;
    snapshot(fd.as_fd(), None)?.captured_return(
        tap,
        targets
            .iter()
            .map(|target| target.target.capture().authority.ifindex),
    )
}

const NATIVE_LINK_CAPACITY: usize = 65_536;
const NATIVE_DRAIN_DATAGRAMS: usize = 64;
// Both v6.12 and v7.2.5 include/uapi/linux/snmp.h define these exact schemas.
const IPSTATS_MIB_SCHEMA: usize = 38;
const ICMP6_MIB_SCHEMA: usize = 7;
const SUPPORTED_IPV6_MIB_SCHEMAS: [(usize, usize); 2] = [
    (IPSTATS_MIB_SCHEMA, ICMP6_MIB_SCHEMA), // v6.12
    (IPSTATS_MIB_SCHEMA, ICMP6_MIB_SCHEMA), // v7.2.5
];

#[cfg(test)]
type NativeReceiveHook = Box<dyn FnMut(&mut [u8]) -> io::Result<usize> + Send>;

pub(crate) struct NativeWatch {
    fd: OwnedFd,
    invalidated: bool,
    receive: Vec<u8>,
    baseline: Vec<u8>,
    observed: Vec<u8>,
    _reservation: MemoryReservation,
    #[cfg(test)]
    consumed: usize,
    #[cfg(test)]
    before_setter: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(test)]
    receive_hook: Option<NativeReceiveHook>,
}

pub(crate) struct NativeUpdateOutcome {
    pub transport: Result<(), crate::bpf::XdpUpdateError>,
    pub observation: io::Result<()>,
}

#[derive(Clone, Copy)]
enum NativeOperation {
    Replace(u32),
    Detach,
    CloseTap,
}

impl NativeOperation {
    fn notifications(self) -> usize {
        match self {
            Self::Replace(_) | Self::Detach => 1,
            Self::CloseTap => 2,
        }
    }
}

#[derive(Clone, Copy)]
enum NativeXdp {
    Present(u32),
    Absent,
}

impl NativeXdpUpdates {
    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, NativeWatch> {
        match self.0.lock() {
            Ok(watch) => watch,
            Err(poisoned) => {
                let mut watch = poisoned.into_inner();
                watch.invalidated = true;
                watch
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn consumed_operations(&self) -> usize {
        self.lock().consumed
    }

    #[cfg(test)]
    pub(crate) fn before_next_setter(&self, hook: impl FnOnce() + Send + 'static) {
        self.lock().before_setter = Some(Box::new(hook));
    }
}

fn watch_failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "XDP topology authority changed; restart required",
    )
}

impl NativeWatch {
    pub(crate) fn invalidate(&mut self) {
        self.invalidated = true;
    }

    pub(crate) fn check_changed(&mut self) -> io::Result<bool> {
        if self.invalidated {
            return Ok(true);
        }
        match self.drain(None) {
            Ok(_) => Ok(false),
            Err(error) => {
                self.invalidated = true;
                Err(error)
            }
        }
    }

    pub(crate) fn check(&mut self) -> io::Result<()> {
        if self.check_changed()? {
            Err(watch_failed())
        } else {
            Ok(())
        }
    }

    pub(crate) fn update(
        &mut self,
        ifindex: u32,
        next: BorrowedFd<'_>,
        next_id: u32,
        old: BorrowedFd<'_>,
        old_id: u32,
        terminal: bool,
    ) -> NativeUpdateOutcome {
        self.update_with(
            ifindex,
            old_id,
            next_id,
            terminal,
            |projection| query_native_link(ifindex, old_id, projection),
            || crate::bpf::set_xdp(ifindex, next.as_raw_fd(), Some(old.as_raw_fd())),
        )
    }

    pub(crate) fn detach_private_xdp(
        &mut self,
        ifindex: u32,
        old: BorrowedFd<'_>,
        old_id: u32,
    ) -> NativeUpdateOutcome {
        self.operation_with(
            ifindex,
            NativeOperation::Detach,
            false,
            |projection| {
                if old_id == 0 {
                    return Err(malformed("invalid Native detach identity"));
                }
                query_native_link(ifindex, old_id, projection)
            },
            || crate::bpf::set_xdp(ifindex, -1, Some(old.as_raw_fd())),
            |projection| query_native_link_state(ifindex, NativeXdp::Absent, projection),
        )
    }

    pub(crate) fn close_private_tap(
        &mut self,
        ifindex: u32,
        close: impl FnOnce() -> io::Result<()>,
    ) -> NativeUpdateOutcome {
        self.operation_with(
            ifindex,
            NativeOperation::CloseTap,
            false,
            |projection| query_native_link_state(ifindex, NativeXdp::Absent, projection),
            || close().map_err(crate::bpf::XdpUpdateError::Uncertain),
            |projection| {
                require_private_tap_absence(query_native_link_state(
                    ifindex,
                    NativeXdp::Absent,
                    projection,
                ))
            },
        )
    }

    fn update_with(
        &mut self,
        ifindex: u32,
        old_id: u32,
        next_id: u32,
        terminal: bool,
        query: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
        setter: impl FnOnce() -> Result<(), crate::bpf::XdpUpdateError>,
    ) -> NativeUpdateOutcome {
        self.operation_with(
            ifindex,
            NativeOperation::Replace(next_id),
            terminal,
            |projection| {
                if old_id == 0 || next_id == 0 {
                    return Err(malformed("invalid Native update identity"));
                }
                query(projection)
            },
            setter,
            |_| Ok(()),
        )
    }

    fn operation_with(
        &mut self,
        ifindex: u32,
        operation: NativeOperation,
        terminal: bool,
        query: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
        setter: impl FnOnce() -> Result<(), crate::bpf::XdpUpdateError>,
        postcheck: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
    ) -> NativeUpdateOutcome {
        let precheck = (|| {
            self.check()?;
            if ifindex == 0 {
                return Err(malformed("invalid Native update identity"));
            }
            self.baseline.clear();
            query(&mut self.baseline)?;
            self.check()?;
            if matches!(operation, NativeOperation::CloseTap) {
                private_tap_down(&mut self.baseline)?;
            }
            Ok(())
        })();
        if precheck.is_err() {
            self.invalidated = true;
            if !terminal || !matches!(operation, NativeOperation::Replace(_)) {
                self.baseline.clear();
                self.observed.clear();
                return NativeUpdateOutcome {
                    transport: Err(crate::bpf::XdpUpdateError::NotAttempted(watch_failed())),
                    observation: precheck,
                };
            }
        }
        #[cfg(test)]
        if let Some(hook) = self.before_setter.take() {
            hook();
        }
        let transport = setter();
        let observation = if precheck.is_err() {
            // A failed observer cannot veto the exact-old terminal guard.
            let _ = self.drain(None);
            precheck
        } else {
            match &transport {
                Ok(()) => self.drain(Some((ifindex, operation))).and_then(|count| {
                    if count == operation.notifications() {
                        Ok(())
                    } else {
                        Err(malformed("missing Native owned link notification"))
                    }
                }),
                Err(
                    crate::bpf::XdpUpdateError::NotAttempted(_)
                    | crate::bpf::XdpUpdateError::Rejected(_),
                ) => self.drain(None).map(|_| ()),
                Err(crate::bpf::XdpUpdateError::Uncertain(_))
                    if matches!(operation, NativeOperation::CloseTap) =>
                {
                    match self.drain(Some((ifindex, operation))) {
                        Err(error) => Err(error),
                        Ok(_) => Err(watch_failed()),
                    }
                }
                Err(crate::bpf::XdpUpdateError::Uncertain(_)) => {
                    let _ = self.drain(None);
                    Err(watch_failed())
                }
            }
        };
        let observation = match (observation, postcheck(&mut self.observed)) {
            (Err(error), Err(post)) => Err(io::Error::new(
                error.kind(),
                format!("{error}; Native link postcondition: {post}"),
            )),
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        };
        if observation.is_err() {
            self.invalidated = true;
        }
        #[cfg(test)]
        if transport.is_ok() && observation.is_ok() {
            self.consumed += 1;
        }
        self.baseline.clear();
        self.observed.clear();
        NativeUpdateOutcome {
            transport,
            observation,
        }
    }

    fn drain(&mut self, expected: Option<(u32, NativeOperation)>) -> io::Result<usize> {
        let mut count = 0usize;
        let mut datagrams = 0usize;
        loop {
            datagrams += 1;
            if datagrams > NATIVE_DRAIN_DATAGRAMS {
                return Err(malformed("Native notification capacity exceeded"));
            }
            #[cfg(test)]
            let received = match self.receive_hook.as_mut() {
                Some(receive) => receive(&mut self.receive),
                None => receive_native(self.fd.as_fd(), &mut self.receive),
            };
            #[cfg(not(test))]
            let received = receive_native(self.fd.as_fd(), &mut self.receive);
            match received {
                Ok(length) => {
                    let Some((ifindex, operation)) = expected else {
                        return Err(watch_failed());
                    };
                    match_native_datagram(
                        &self.receive[..length],
                        ifindex,
                        operation,
                        &mut count,
                        &mut self.baseline,
                        &mut self.observed,
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(count),
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
#[path = "topology/native_updates_tests.rs"]
mod native_updates_tests;

fn receive_native(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: zero initializes the writable source address and all buffers stay live.
    let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut extent = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let length = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            (&mut source as *mut libc::sockaddr_nl).cast(),
            &mut extent,
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    validate_native_receive(length as usize, buffer.len(), extent, &source)
}

fn validate_native_receive(
    length: usize,
    buffer_len: usize,
    extent: libc::socklen_t,
    source: &libc::sockaddr_nl,
) -> io::Result<usize> {
    if length == 0
        || length > buffer_len
        || extent as usize != size_of::<libc::sockaddr_nl>()
        || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || source.nl_pid != 0
    {
        return Err(malformed(
            "invalid Native link notification sender or extent",
        ));
    }
    Ok(length)
}

fn query_native_link(ifindex: u32, old_id: u32, projection: &mut Vec<u8>) -> io::Result<()> {
    query_native_link_state(ifindex, NativeXdp::Present(old_id), projection)
}

fn query_native_link_state(
    ifindex: u32,
    xdp: NativeXdp,
    projection: &mut Vec<u8>,
) -> io::Result<()> {
    let mut request = [0u8; 32];
    request[..4].copy_from_slice(&32u32.to_ne_bytes());
    request[4..6].copy_from_slice(&18u16.to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    let mut buffer = [0u8; NATIVE_LINK_CAPACITY];
    crate::bpf::exchange_netlink_buffer(&request, &mut buffer, |bytes| {
        parse_native_link_reply(bytes, &request, xdp, projection)
    })
}

fn parse_native_link_reply(
    bytes: &[u8],
    request: &[u8; 32],
    xdp: NativeXdp,
    projection: &mut Vec<u8>,
) -> io::Result<Option<()>> {
    let mut found = false;
    let mut errno = None;
    native_messages(bytes, |message| {
        if found || u32_at(message, 8)? != 1 || u16::from_ne_bytes([message[6], message[7]]) != 0 {
            return Err(malformed("unexpected Native GETLINK response"));
        }
        match u16::from_ne_bytes([message[4], message[5]]) {
            16 => match xdp {
                NativeXdp::Present(program) => native_link_projection(
                    &message[16..],
                    u32_at(request, 20)?,
                    program,
                    projection,
                )?,
                NativeXdp::Absent => native_link_projection_state(
                    &message[16..],
                    u32_at(request, 20)?,
                    xdp,
                    0,
                    projection,
                )?,
            },
            2 if message.len() == 52 && message[20..] == request[..] => {
                let error = i32::from_ne_bytes(message[16..20].try_into().unwrap());
                errno = Some(
                    error
                        .checked_neg()
                        .filter(|&value| value > 0)
                        .ok_or_else(|| malformed("invalid Native GETLINK errno"))?,
                );
            }
            _ => return Err(malformed("unexpected Native GETLINK response")),
        }
        found = true;
        Ok(())
    })?;
    match errno {
        Some(errno) => Err(io::Error::from_raw_os_error(errno)),
        None => Ok(found.then_some(())),
    }
}

fn require_private_tap_absence(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(malformed("private TAP still exists after close")),
    }
}

fn native_messages(
    mut bytes: &[u8],
    mut visit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(malformed("empty Native netlink datagram"));
    }
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(malformed("short Native netlink header"));
        }
        let length = u32_at(bytes, 0)? as usize;
        if length < 16 || length > bytes.len() {
            return Err(malformed("invalid Native netlink extent"));
        }
        let advance = crate::bpf::aligned_extent(length, bytes.len())?;
        visit(&bytes[..length])?;
        bytes = &bytes[advance..];
    }
    Ok(())
}

fn match_native_datagram(
    bytes: &[u8],
    ifindex: u32,
    operation: NativeOperation,
    count: &mut usize,
    baseline: &mut Vec<u8>,
    observed: &mut Vec<u8>,
) -> io::Result<()> {
    native_messages(bytes, |message| {
        if *count >= operation.notifications() {
            return Err(malformed("extra Native owned link notification"));
        }
        let (kind, change, xdp) = match operation {
            NativeOperation::Replace(program) => (16, 0, NativeXdp::Present(program)),
            NativeOperation::Detach => (16, 0, NativeXdp::Absent),
            NativeOperation::CloseTap if *count == 0 => (
                16,
                (libc::IFF_UP | libc::IFF_RUNNING) as u32,
                NativeXdp::Absent,
            ),
            NativeOperation::CloseTap => {
                private_tap_delete(baseline)?;
                (17, u32::MAX, NativeXdp::Absent)
            }
        };
        if u16::from_ne_bytes([message[4], message[5]]) != kind
            || message[6..16].iter().any(|&byte| byte != 0)
        {
            return Err(malformed("unexpected Native link notification header"));
        }
        native_link_projection_state(&message[16..], ifindex, xdp, change, observed)?;
        if observed.as_slice() != baseline.as_slice() {
            return Err(malformed("Native link configuration changed"));
        }
        *count += 1;
        Ok(())
    })
}

fn native_link_projection(
    body: &[u8],
    ifindex: u32,
    program: u32,
    output: &mut Vec<u8>,
) -> io::Result<()> {
    native_link_projection_state(body, ifindex, NativeXdp::Present(program), 0, output)
}

fn native_link_projection_state(
    body: &[u8],
    ifindex: u32,
    xdp_state: NativeXdp,
    change: u32,
    output: &mut Vec<u8>,
) -> io::Result<()> {
    if body.len() < 16
        || body[0] != 0
        || body[1] != 0
        || u32_at(body, 4)? != ifindex
        || u32_at(body, 12)? != change
    {
        return Err(malformed("Native link identity mismatch"));
    }
    output.clear();
    projection_append(output, &body[..12])?;
    let mut xdp = false;
    native_attributes(&body[16..], 0, output, &mut |value| {
        if xdp {
            return Err(malformed("duplicate Native XDP nest"));
        }
        match xdp_state {
            NativeXdp::Present(program) => {
                crate::bpf::strict_native_xdp(value, program)?;
            }
            NativeXdp::Absent => strict_native_xdp_absent(value)?,
        }
        xdp = true;
        Ok(())
    })?;
    if !xdp {
        return Err(malformed("missing Native XDP nest"));
    }
    Ok(())
}

fn strict_native_xdp_absent(bytes: &[u8]) -> io::Result<()> {
    let mut found = false;
    // rtnl_xdp_fill in v6.12/v7.2.5 emits only ATTACHED=NONE without IDs.
    crate::bpf::raw_attributes(bytes, |kind, value| {
        if found || kind != 2 || value != [0] {
            return Err(malformed("invalid absent Native XDP nest"));
        }
        found = true;
        Ok(())
    })?;
    if !found {
        return Err(malformed("missing absent Native XDP state"));
    }
    Ok(())
}

fn private_tap_down(projection: &mut [u8]) -> io::Result<()> {
    let flags = u32_at(projection, 8)?;
    if flags & libc::IFF_UP as u32 == 0 {
        return Err(malformed("private TAP is not UP before close"));
    }
    let mut seen = 0u8;
    let mut offset = 12;
    while offset < projection.len() {
        let kind = u16::from_ne_bytes([projection[offset], projection[offset + 1]]) & 0x3fff;
        let length = u32_at(projection, offset + 2)? as usize;
        let value = &mut projection[offset + 6..offset + 6 + length];
        match kind {
            6 | 26 => seen |= if kind == 6 { 1 } else { 2 },
            16 | 33 => {
                if value.len() != 1 || (kind == 33 && value != [1]) {
                    return Err(malformed("invalid private TAP carrier or operstate"));
                }
                value[0] = if kind == 16 { 2 } else { 0 };
                seen |= if kind == 16 { 4 } else { 8 };
            }
            35 | 47 | 48 => {
                let counter = exact_u32(value)?;
                if kind != 47 {
                    value.copy_from_slice(&counter.wrapping_add(1).to_ne_bytes());
                }
                seen |= match kind {
                    35 => 16,
                    47 => 32,
                    _ => 64,
                };
            }
            _ => {}
        }
        offset += 6 + length;
    }
    if seen != 127 {
        return Err(malformed("missing private TAP close state"));
    }
    // tun last-file release holds RTNL through carrier-off and unregister. In
    // v6.12/v7.2.5 dev_close_many clears UP before linkwatch can emit again;
    // its DOWN notification precedes protocol DOWN handlers and qdisc shutdown.
    let flags = flags
        & !((libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_LOWER_UP | libc::IFF_DORMANT) as u32);
    projection[8..12].copy_from_slice(&flags.to_ne_bytes());
    Ok(())
}

fn private_tap_delete(projection: &mut Vec<u8>) -> io::Result<()> {
    let mut offset = 12;
    while offset < projection.len() {
        let kind = u16::from_ne_bytes([projection[offset], projection[offset + 1]]) & 0x3fff;
        let length = u32_at(projection, offset + 2)? as usize;
        let start = offset + 6;
        let end = start + length;
        let replacement = match kind {
            6 => {
                // dev_shutdown selects noop before RTM_DELLINK is serialized.
                if length < 5 {
                    let tail = projection.len();
                    projection_zeroes(projection, 5 - length)?;
                    projection.copy_within(end..tail, end + 5 - length);
                }
                projection[start..start + 5].copy_from_slice(b"noop\0");
                5
            }
            26 => {
                // IPv4/IPv6 unregister clear ip_ptr/ip6_ptr; rtnl AF emitters
                // return ENODATA. Keep the container and all other families.
                let mut read = start;
                let mut write = start;
                while read < end {
                    let family =
                        u16::from_ne_bytes([projection[read], projection[read + 1]]) & 0x3fff;
                    let extent = 6 + u32_at(projection, read + 2)? as usize;
                    if family != libc::AF_INET as u16 && family != libc::AF_INET6 as u16 {
                        if read != write {
                            projection.copy_within(read..read + extent, write);
                        }
                        write += extent;
                    }
                    read += extent;
                }
                write - start
            }
            _ => length,
        };
        if replacement != length {
            projection[offset + 2..offset + 6].copy_from_slice(&(replacement as u32).to_ne_bytes());
        }
        if replacement < length {
            projection.copy_within(end.., start + replacement);
            projection.truncate(projection.len() - (length - replacement));
        }
        offset = start + replacement;
    }
    Ok(())
}

fn projection_append(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    if output.len().saturating_add(value.len()) > NATIVE_LINK_CAPACITY {
        return Err(malformed("Native link projection capacity exceeded"));
    }
    output.extend_from_slice(value);
    Ok(())
}

fn projection_zeroes(output: &mut Vec<u8>, length: usize) -> io::Result<()> {
    let end = output.len().saturating_add(length);
    if end > NATIVE_LINK_CAPACITY {
        return Err(malformed("Native link projection capacity exceeded"));
    }
    output.resize(end, 0);
    Ok(())
}

fn native_attributes(
    bytes: &[u8],
    level: u8,
    output: &mut Vec<u8>,
    xdp: &mut impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut seen = [0u64; 256];
    crate::bpf::raw_attributes(bytes, |raw_kind, value| {
        let kind = raw_kind & 0x3fff;
        if level == 1 || raw_kind & 0x8000 != 0 || (level == 0 && kind == 52) {
            validate_native_nested(value, 0)?;
        }
        if level == 0 && kind == 42 {
            if !value.is_empty() {
                return Err(malformed("nonempty link PAD"));
            }
            return Ok(());
        }
        let word = &mut seen[usize::from(kind) / 64];
        let bit = 1u64 << (kind % 64);
        if *word & bit != 0 {
            return Err(malformed("duplicate Native link attribute"));
        }
        *word |= bit;
        if level == 0 && kind == 43 {
            return xdp(value);
        }
        projection_append(output, &raw_kind.to_ne_bytes())?;
        let length_offset = output.len();
        projection_append(output, &[0; 4])?;
        let start = output.len();
        match (level, kind) {
            (0, 7 | 23) => {
                let expected = if kind == 7 { 96 } else { 200 };
                if value.len() != expected {
                    return Err(malformed("unsupported link statistics schema"));
                }
                projection_zeroes(output, expected)?;
            }
            (0, 26) => native_attributes(value, 1, output, xdp)?,
            (1, 10) => native_attributes(value, 2, output, xdp)?,
            (2, 3 | 6) => {
                if !SUPPORTED_IPV6_MIB_SCHEMAS.iter().any(|&(ipstats, icmp6)| {
                    let count = if kind == 3 { ipstats } else { icmp6 };
                    value.len() == count * 8
                        && u64::from_ne_bytes(value[..8].try_into().unwrap()) == count as u64
                }) {
                    return Err(malformed("unsupported IPv6 MIB schema"));
                }
                projection_append(output, &value[..8])?;
                projection_zeroes(output, value.len() - 8)?;
            }
            _ => projection_append(output, value)?,
        }
        let length = (output.len() - start) as u32;
        output[length_offset..length_offset + 4].copy_from_slice(&length.to_ne_bytes());
        Ok(())
    })
}

fn validate_native_nested(bytes: &[u8], depth: usize) -> io::Result<()> {
    if depth >= 8 {
        return Err(malformed("Native link nesting capacity exceeded"));
    }
    crate::bpf::raw_attributes(bytes, |kind, value| {
        if kind & 0x8000 != 0 {
            validate_native_nested(value, depth + 1)?;
        }
        Ok(())
    })
}

impl AsFd for Topology {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Topology {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn malformed(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_xdp_admission_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "XDP topology admission deadline expired",
        ));
    }
    Ok(())
}

struct PendingCarrier {
    index: u32,
    name: Option<[u8; 16]>,
}

fn settle_xdp_carrier<W, T>(
    deadline: Instant,
    mut snapshot: impl FnMut(Instant) -> io::Result<(W, Option<PendingCarrier>)>,
    mut wait: impl FnMut(W, Instant) -> io::Result<()>,
    admit: impl FnOnce(Option<Instant>) -> io::Result<T>,
    mut now: impl FnMut() -> Instant,
) -> io::Result<T> {
    let mut previous = None::<PendingCarrier>;
    loop {
        let (watch, pending) = snapshot(deadline).map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut
                && now() >= deadline
                && let Some(link) = &previous
            {
                xdp_carrier_timeout(link)
            } else {
                error
            }
        })?;
        let Some(link) = pending else {
            return admit(Some(deadline));
        };
        if now() >= deadline {
            return Err(xdp_carrier_timeout(&link));
        }
        wait(watch, deadline).map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                xdp_carrier_timeout(&link)
            } else {
                error
            }
        })?;
        previous = Some(link);
    }
}

fn xdp_carrier_timeout(link: &PendingCarrier) -> io::Error {
    let message = match &link.name {
        Some(name) => format!(
            "{}: no carrier after XDP attach",
            String::from_utf8_lossy(name).trim_end_matches('\0')
        ),
        None => format!("ifindex {}: no carrier after XDP attach", link.index),
    };
    io::Error::new(io::ErrorKind::TimedOut, message)
}

fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| malformed("short routing integer"))?
            .try_into()
            .unwrap(),
    ))
}

fn unicast_source(family: u8, bytes: &[u8]) -> io::Result<bool> {
    let address = match (family, bytes.len()) {
        (2, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())),
        (10, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        _ => return Err(malformed("invalid topology address extent")),
    };
    Ok(!address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(ip) if ip.is_broadcast()))
}

fn validate_capture_sets(
    captured_physical: &[u32],
    captured_logical: &[u32],
    bypass_mark: u32,
) -> io::Result<()> {
    if captured_physical.is_empty() != captured_logical.is_empty()
        || bypass_mark == 0
        || bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
        || captured_physical.len() > MAX_OBJECTS
        || captured_logical.len() > MAX_OBJECTS
    {
        return Err(unsupported(
            "invalid physical/logical capture sets or bypass mark",
        ));
    }
    let physical: HashSet<_> = captured_physical.iter().copied().collect();
    let logical: HashSet<_> = captured_logical.iter().copied().collect();
    if physical.len() != captured_physical.len()
        || logical.len() != captured_logical.len()
        || logical.contains(&0)
        || !physical.is_subset(&logical)
    {
        return Err(unsupported(
            "invalid physical/logical capture sets or bypass mark",
        ));
    }
    Ok(())
}

/// Reads cleanup evidence without requiring the topology to remain admissible.
/// Unrepresentable occupants retain their slot and have no deletable key.
pub fn tun_readback(spec: &TunSpec<'_>, ifindex: u32) -> io::Result<TunReadback> {
    spec.validate()?;
    let fd = route_socket(false)?;
    snapshot(fd.as_fd(), None)?.tun_readback(spec, ifindex)
}

fn snapshot(fd: BorrowedFd<'_>, deadline: Option<Instant>) -> io::Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    for (sequence, kind, body_len) in [(1, 18, 16), (2, 22, 8), (3, 34, 12), (4, 26, 12)] {
        dump(
            fd,
            sequence,
            kind,
            body_len,
            &mut snapshot,
            deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(2)),
        )?;
    }
    Ok(snapshot)
}

fn interface_name(bytes: &[u8]) -> io::Result<[u8; 16]> {
    if bytes.is_empty() || bytes.len() >= 16 || bytes.contains(&0) {
        return Err(malformed("invalid topology interface name"));
    }
    let mut name = [0; 16];
    name[..bytes.len()].copy_from_slice(bytes);
    Ok(name)
}

fn netlink_name(bytes: &[u8]) -> io::Result<[u8; 16]> {
    let Some((&0, name)) = bytes.split_last() else {
        return Err(malformed("unterminated topology interface name"));
    };
    interface_name(name)
}

fn ip_address(family: u8, bytes: &[u8]) -> io::Result<IpAddr> {
    match (family, bytes.len()) {
        (2, 4) => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).unwrap(),
        ))),
        (10, 16) => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap(),
        ))),
        _ => Err(malformed("invalid topology address extent")),
    }
}

fn unspecified(family: u8) -> Option<IpAddr> {
    match family {
        2 => Some(Ipv4Addr::UNSPECIFIED.into()),
        10 => Some(Ipv6Addr::UNSPECIFIED.into()),
        _ => None,
    }
}

fn network_address(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(ip) => {
            prefix <= 32 && u32::from(ip).checked_shl(prefix.into()).unwrap_or(0) == 0
        }
        IpAddr::V6(ip) => {
            prefix <= 128 && u128::from(ip).checked_shl(prefix.into()).unwrap_or(0) == 0
        }
    }
}

fn exact_u32(bytes: &[u8]) -> io::Result<u32> {
    let value = bytes
        .try_into()
        .map_err(|_| malformed("invalid topology integer extent"))?;
    Ok(u32::from_ne_bytes(value))
}

fn unique_attribute(seen: &mut u64, kind: u16) -> io::Result<()> {
    if kind < 64 {
        let bit = 1u64 << kind;
        if *seen & bit != 0 {
            return Err(malformed("duplicate topology attribute"));
        }
        *seen |= bit;
    }
    Ok(())
}

fn route_socket(watch: bool) -> io::Result<OwnedFd> {
    // SAFETY: socket takes scalar arguments and returns a new owned descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket returned this unique descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is valid initialization for sockaddr_nl.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // Subscribe before dumping, including both rule families.
    address.nl_groups = if watch {
        1 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400
    } else {
        0
    };
    // SAFETY: address is complete and alive during bind.
    if unsafe {
        libc::bind(
            raw,
            (&address as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let ipv6_rules: libc::c_int = 19;
    // SAFETY: the supplied option is a live integer, for RTNLGRP_IPV6_RULE.
    if watch
        && unsafe {
            libc::setsockopt(
                raw,
                270,
                1,
                (&ipv6_rules as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn dump(
    fd: BorrowedFd<'_>,
    sequence: u32,
    kind: u16,
    body_len: usize,
    snapshot: &mut Snapshot,
    deadline: Instant,
) -> io::Result<()> {
    let mut request = [0u8; 32];
    let length = 16 + body_len;
    request[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    // SAFETY: zero is valid initialization for sockaddr_nl.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "topology dump deadline expired",
            ));
        }
        // SAFETY: request and kernel match their supplied lengths.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                length,
                libc::MSG_DONTWAIT,
                (&kernel as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n >= 0 {
            if n as usize != length {
                return Err(malformed("short topology dump request"));
            }
            break;
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(error);
        }
        wait_netlink(fd, libc::POLLOUT, deadline)?;
    }
    let mut buffer = [0u8; 65_536];
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "topology dump deadline expired",
            ));
        }
        wait_netlink(fd, libc::POLLIN, deadline)?;
        let mut source = kernel;
        let mut source_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: receive buffers are writable and correctly sized.
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                (&mut source as *mut libc::sockaddr_nl).cast(),
                &mut source_len,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        if n == 0
            || n as usize > buffer.len()
            || source_len as usize != size_of::<libc::sockaddr_nl>()
            || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || source.nl_pid != 0
        {
            return Err(malformed("invalid topology dump sender or extent"));
        }
        let mut bytes = &buffer[..n as usize];
        let mut done = false;
        while !bytes.is_empty() {
            if bytes.len() < 16 {
                return Err(malformed("short topology message"));
            }
            let length = u32_at(bytes, 0)? as usize;
            if length < 16 || length > bytes.len() {
                return Err(malformed("invalid topology message length"));
            }
            let message = u16::from_ne_bytes([bytes[4], bytes[5]]);
            let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
            if u32_at(bytes, 8)? != sequence || flags & 0x10 != 0 {
                return Err(unsupported(
                    "topology changed or dump was interrupted during admission",
                ));
            }
            let body = &bytes[16..length];
            match message {
                2 => {
                    let errno = u32_at(body, 0)? as i32;
                    if errno != 0 {
                        return Err(io::Error::from_raw_os_error(
                            errno
                                .checked_neg()
                                .ok_or_else(|| malformed("invalid topology errno"))?,
                        ));
                    }
                }
                3 => {
                    if body.len() >= 4 && u32_at(body, 0)? != 0 {
                        return Err(malformed("failed topology dump completion"));
                    }
                    done = true;
                }
                4 => return Err(malformed("topology netlink overrun")),
                16 | 20 | 24 | 32 if !done && message == kind - 2 && flags & 2 != 0 => {
                    snapshot.push(message, body)?
                }
                _ => return Err(malformed("unexpected topology dump message")),
            }
            let advance = (length + 3) & !3;
            if advance > bytes.len() && length != bytes.len() {
                return Err(malformed("short topology alignment"));
            }
            bytes = &bytes[advance.min(bytes.len())..];
        }
        if done {
            return Ok(());
        }
    }
}

#[derive(Default)]
struct Snapshot {
    links: Vec<Link>,
    addresses: Vec<Address>,
    rules: Vec<Rule>,
    routes: Vec<Route>,
}

#[derive(Clone)]
struct Link {
    index: u32,
    plain_up_ethernet: bool,
    loopback: bool,
    name: Option<[u8; 16]>,
    mtu: Option<u32>,
    kind: Option<[u8; 16]>,
    flags: u32,
    master: u32,
    arphrd: u16,
}
#[derive(Clone)]
struct Address {
    family: u8,
    index: u32,
    unicast_source: bool,
    address: IpAddr,
    peer: Option<IpAddr>,
    prefix_len: u8,
    flags: u32,
    scope: u8,
    label: Option<[u8; 16]>,
    unsupported: bool,
    permanent: bool,
    preferred: bool,
}
#[derive(Clone)]
struct Rule {
    family: u8,
    priority: u32,
    table: u32,
    mark: Option<u32>,
    mask: u32,
    simple: bool,
    action: u8,
    iif: Option<[u8; 16]>,
    flags: u32,
    unsupported: bool,
}
#[derive(Clone)]
struct Route {
    family: u8,
    table: u32,
    output: u32,
    default: bool,
    kind: u8,
    simple: bool,
    native_multicast: bool,
    native_multicast_linkdown: bool,
    ipv4_destination: Option<Ipv4Addr>,
    destination: Option<IpAddr>,
    prefix_len: u8,
    metric: u32,
    protocol: u8,
    scope: u8,
    flags: u32,
    gateway: Option<IpAddr>,
    source: Option<IpAddr>,
    preference: u8,
    unsupported: bool,
}

impl Snapshot {
    fn captured_return(&self, tap: u32, physical: impl Iterator<Item = u32>) -> io::Result<()> {
        let device = self
            .links
            .iter()
            .find(|link| link.index == tap)
            .ok_or_else(|| unsupported("captured private TAP disappeared"))?;
        let mut kind = [0u8; 16];
        kind[..3].copy_from_slice(b"tun");
        if tap == 0
            || device.kind != Some(kind)
            || device.arphrd != 1
            || device.master != 0
            || device.loopback
            || self.addresses.iter().any(|address| address.index == tap)
            || self.routes.iter().any(|route| route.output == tap)
        {
            return Err(unsupported(
                "captured private TAP must be standalone, unnumbered and unrouted",
            ));
        }
        for index in physical {
            if index == tap
                || !self.links.iter().any(|link| {
                    link.index == index
                        && link.plain_up_ethernet
                        && link.master == 0
                        && !link.loopback
                })
                || self.addresses.iter().any(|address| address.index == index)
            {
                return Err(unsupported(
                    "captured target must remain an unnumbered standalone physical root",
                ));
            }
        }
        Ok(())
    }

    fn ipv4_broadcasts(&self) -> io::Result<([Ipv4Addr; MAX_BROADCASTS], usize)> {
        let mut addresses = [Ipv4Addr::UNSPECIFIED; MAX_BROADCASTS];
        let mut count = 0;
        for route in self
            .routes
            .iter()
            .filter(|route| route.family == 2 && route.table == 255 && route.kind == 3)
        {
            let address = route
                .ipv4_destination
                .filter(|_| route.simple)
                .ok_or_else(|| {
                    unsupported("native broadcast requires a simple local-table IPv4 /32")
                })?;
            if self.routes.iter().any(|other| {
                other.family == 2
                    && other.table == 255
                    && other.ipv4_destination == Some(address)
                    && other.kind != 3
            }) {
                return Err(unsupported("ambiguous local broadcast destination"));
            }
            if addresses[..count].contains(&address) {
                continue;
            }
            if count == MAX_BROADCASTS {
                return Err(unsupported(
                    "native broadcast destinations exceed bounded capacity",
                ));
            }
            addresses[count] = address;
            count += 1;
        }
        addresses[..count].sort_unstable();
        Ok((addresses, count))
    }

    fn push(&mut self, kind: u16, body: &[u8]) -> io::Result<()> {
        if self.links.len() + self.addresses.len() + self.rules.len() + self.routes.len()
            >= MAX_OBJECTS
        {
            return Err(unsupported("topology snapshot exceeds bounded capacity"));
        }
        match kind {
            16 => {
                if body.len() < 16 {
                    return Err(malformed("short topology link"));
                }
                let index = u32_at(body, 4)?;
                let flags = u32_at(body, 8)?;
                let arphrd = u16::from_ne_bytes([body[2], body[3]]);
                let mut link = Link {
                    index,
                    plain_up_ethernet: arphrd == 1 && flags & 1 != 0,
                    loopback: flags & 8 != 0,
                    name: None,
                    mtu: None,
                    kind: None,
                    flags,
                    master: 0,
                    arphrd,
                };
                let mut parent = index;
                let mut seen = 0;
                attributes(&body[16..], |kind, value| {
                    match kind {
                        3 | 4 | 5 | 10 | 18 => unique_attribute(&mut seen, kind)?,
                        _ => {}
                    }
                    match kind {
                        3 => link.name = Some(netlink_name(value)?),
                        4 => link.mtu = Some(exact_u32(value)?),
                        5 => parent = exact_u32(value)?,
                        10 => {
                            link.master = exact_u32(value)?;
                            link.plain_up_ethernet &= link.master == 0;
                        }
                        18 => {
                            let mut seen_info = 0;
                            attributes(value, |kind, value| {
                                if kind == 1 {
                                    unique_attribute(&mut seen_info, kind)?;
                                    link.kind = Some(netlink_name(value)?);
                                }
                                Ok(())
                            })?;
                        }
                        _ => {}
                    }
                    Ok(())
                })?;
                link.plain_up_ethernet &= match link.kind {
                    Some(name) if name == interface_name(b"veth")? => true,
                    None => parent == index,
                    _ => false,
                };
                self.links.push(link);
            }
            20 => {
                if body.len() < 8 {
                    return Err(malformed("short topology address"));
                }
                let family = body[0];
                if !matches!(family, 2 | 10) {
                    return Ok(());
                }
                let mut address = None;
                let mut local = None;
                let mut flags = u32::from(body[2]);
                let mut label = None;
                let mut unsupported = false;
                let mut permanent = true;
                let mut preferred = true;
                let mut seen = 0;
                attributes(&body[8..], |kind, value| {
                    unique_attribute(&mut seen, kind)?;
                    match kind {
                        1 => address = Some(ip_address(family, value)?),
                        2 => local = Some(ip_address(family, value)?),
                        3 => label = Some(netlink_name(value)?),
                        6 => {
                            if value.len() != 16 {
                                return Err(malformed("invalid topology address cache info"));
                            }
                            permanent =
                                u32_at(value, 0)? == u32::MAX && u32_at(value, 4)? == u32::MAX;
                            preferred = u32_at(value, 0)? != 0 && u32_at(value, 4)? != 0;
                        }
                        8 => flags = exact_u32(value)?,
                        11 if value.len() == 1 && value[0] == 0 => {}
                        _ => unsupported = true,
                    }
                    Ok(())
                })?;
                let ip = local
                    .or(address)
                    .ok_or_else(|| malformed("missing topology source address"))?;
                let unicast_source = match ip {
                    IpAddr::V4(ip) => unicast_source(family, &ip.octets())?,
                    IpAddr::V6(ip) => unicast_source(family, &ip.octets())?,
                };
                self.addresses.push(Address {
                    family,
                    index: u32_at(body, 4)?,
                    unicast_source,
                    address: ip,
                    peer: address.filter(|peer| *peer != ip),
                    prefix_len: body[1],
                    flags,
                    scope: body[3],
                    label,
                    unsupported,
                    permanent,
                    preferred,
                });
            }
            32 => {
                if body.len() < 12 {
                    return Err(malformed("short topology rule"));
                }
                let flags = u32_at(body, 8)?;
                let mut rule = Rule {
                    family: body[0],
                    priority: 0,
                    table: u32::from(body[4]),
                    mark: None,
                    mask: 0,
                    simple: body[1..4] == [0, 0, 0] && body[7] == 1 && flags == 0,
                    action: body[7],
                    iif: None,
                    flags,
                    unsupported: body[1..4] != [0, 0, 0] || body[5..7] != [0, 0],
                };
                let mut seen = 0;
                attributes(&body[12..], |kind, value| {
                    unique_attribute(&mut seen, kind)?;
                    match kind {
                        3 => {
                            rule.iif = Some(netlink_name(value)?);
                            rule.simple = false;
                        }
                        6 => rule.priority = exact_u32(value)?,
                        10 => rule.mark = Some(exact_u32(value)?),
                        15 => rule.table = exact_u32(value)?,
                        16 => rule.mask = exact_u32(value)?,
                        14 if exact_u32(value)? == u32::MAX => {}
                        18 if value.is_empty() => {}
                        21 if value.len() == 1 => {}
                        _ => {
                            rule.simple = false;
                            rule.unsupported = true;
                        }
                    }
                    Ok(())
                })?;
                self.rules.push(rule);
            }
            24 => {
                if body.len() < 12 {
                    return Err(malformed("short topology route"));
                }
                let mut route = Route {
                    family: body[0],
                    table: u32::from(body[4]),
                    output: 0,
                    default: body[1] == 0,
                    kind: body[7],
                    simple: body[2] == 0 && body[3] == 0,
                    native_multicast: body[0] == 10 && body[1] == 8 && body[7] == 5,
                    native_multicast_linkdown: false,
                    ipv4_destination: None,
                    destination: unspecified(body[0]),
                    prefix_len: body[1],
                    metric: 0,
                    protocol: body[5],
                    scope: body[6],
                    flags: u32_at(body, 8)?,
                    gateway: None,
                    source: None,
                    preference: 0,
                    unsupported: body[2] != 0 || body[3] != 0,
                };
                let mut multicast_destination = None;
                let mut seen = 0;
                attributes(&body[12..], |kind, value| {
                    unique_attribute(&mut seen, kind)?;
                    match kind {
                        1 => {
                            multicast_destination = Some(
                                value.len() == 16
                                    && value[0] == 0xff
                                    && value[1..].iter().all(|&byte| byte == 0),
                            );
                            // XDP historically refuses malformed non-/32 destinations at
                            // admission rather than parsing them as usable multicast.
                            route.destination = ip_address(route.family, value).ok();
                            if body[0] == 2 && body[1] == 32 {
                                route.ipv4_destination = Some(Ipv4Addr::from(
                                    <[u8; 4]>::try_from(value)
                                        .map_err(|_| malformed("invalid IPv4 route destination"))?,
                                ));
                            }
                        }
                        4 => route.output = exact_u32(value)?,
                        5 => route.gateway = Some(ip_address(route.family, value)?),
                        6 => route.metric = exact_u32(value)?,
                        7 => route.source = Some(ip_address(route.family, value)?),
                        12 => {
                            if value.len() != 32 {
                                return Err(malformed("invalid topology route cache info"));
                            }
                            route.unsupported |= u32_at(value, 8)? != 0 || u32_at(value, 12)? != 0;
                        }
                        15 => route.table = exact_u32(value)?,
                        20 if value.len() == 1 && matches!(value[0], 0 | 1 | 3) => {
                            route.preference = value[0];
                        }
                        8 | 23 => route.unsupported = true,
                        _ => {
                            route.simple = false;
                            route.unsupported = true;
                        }
                    }
                    Ok(())
                })?;
                route.unsupported |= route
                    .destination
                    .is_none_or(|ip| !network_address(ip, route.prefix_len))
                    || (route.prefix_len != 0 && multicast_destination.is_none());
                route.native_multicast &= route.simple && multicast_destination == Some(true);
                // The first native XDP attachment can temporarily mark this route LINKDOWN.
                route.native_multicast_linkdown =
                    route.native_multicast && !route.unsupported && route.flags == RTNH_F_LINKDOWN;
                route.simple &= route.flags == 0;
                route.native_multicast &= route.simple;
                self.routes.push(route);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn admit_tun(
        &self,
        spec: &TunSpec<'_>,
        name: [u8; 16],
        owned: Option<(u32, TunStage)>,
    ) -> io::Result<()> {
        if self.tun_ready(
            spec,
            name,
            owned.map(|(index, _)| index),
            owned.map(|(_, stage)| stage),
        )? {
            Ok(())
        } else {
            Err(unsupported("owned TUN address lacks its exact local route"))
        }
    }

    fn tun_ready(
        &self,
        spec: &TunSpec<'_>,
        name: [u8; 16],
        ifindex: Option<u32>,
        stage: Option<TunStage>,
    ) -> io::Result<bool> {
        let mut indices = HashSet::new();
        let mut names = HashSet::new();
        let vrf = interface_name(b"vrf")?;
        for link in &self.links {
            if link.index == 0
                || !indices.insert(link.index)
                || link.name.is_none_or(|name| !names.insert(name))
                || link.kind == Some(vrf)
            {
                return Err(unsupported("TUN requires unique named links without VRFs"));
            }
        }
        if let Some(index) = ifindex {
            if !self.tun_link(spec, index) {
                return Err(unsupported(
                    "owned TUN name, MTU, kind, flags or master changed",
                ));
            }
        } else if self.links.iter().any(|link| link.name == Some(name)) {
            return Err(unsupported("TUN name is already occupied"));
        }
        let expected_addresses: Vec<_> = spec.addresses().collect();
        let mut found_addresses = HashSet::new();
        for address in &self.addresses {
            if Some(address.index) == ifindex {
                let flags = IFA_F_PERMANENT
                    | IFA_F_NOPREFIXROUTE
                    | if address.family == 10 { IFA_F_NODAD } else { 0 };
                if !expected_addresses.contains(&address.address)
                    || !found_addresses.insert(address.address)
                    || address.prefix_len != if address.family == 2 { 32 } else { 128 }
                    || address.flags != flags
                    || address.scope != 0
                    || address.peer.is_some()
                    || address.unsupported
                    || !address.permanent
                    || address.label.is_some_and(|label| label != name)
                {
                    return Err(unsupported(
                        "owned TUN addresses do not match the exact permanent host keys",
                    ));
                }
            } else if expected_addresses.contains(&address.address)
                || address
                    .peer
                    .is_some_and(|peer| expected_addresses.contains(&peer))
            {
                return Err(unsupported(
                    "TUN address is already occupied on another link",
                ));
            }
        }
        if ifindex.is_some() && found_addresses.len() != expected_addresses.len() {
            return Err(unsupported("owned TUN address is missing"));
        }
        let mut ready = true;
        if let Some(index) = ifindex {
            for address in &expected_addresses {
                let family = if address.is_ipv4() { 2 } else { 10 };
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                let mut local = self.routes.iter().filter(|route| {
                    route.family == family
                        && route.table == 255
                        && route.destination == Some(*address)
                        && route.prefix_len == prefix
                });
                match (local.next(), local.next()) {
                    (None, None) if address.is_ipv6() => ready = false,
                    (Some(route), None) if route.kind == 2 && route.output == index => {}
                    _ => {
                        return Err(unsupported(
                            "owned TUN local route is missing, conflicting or duplicated",
                        ));
                    }
                }
            }
        }
        let expected_rules = spec.rules();
        let mut seen_rules = Vec::with_capacity(expected_rules.len());
        for rule in &self.rules {
            let reserved = (spec.rule_priority..=spec.rule_priority + 4).contains(&rule.priority);
            if reserved {
                let key = ifindex.zip(stage).and_then(|(index, _)| {
                    self.tun_rule_key(spec, &expected_rules, rule, index, false)
                });
                if key.is_none() || seen_rules.contains(&key) {
                    return Err(unsupported(
                        "TUN priority range contains a foreign or duplicate rule",
                    ));
                }
                seen_rules.push(key);
            } else if rule.table == spec.table {
                return Err(unsupported("another rule references the TUN capture table"));
            } else if matches!(rule.family, 2 | 10) && !Self::system_tun_rule(rule) {
                return Err(unsupported(
                    "TUN requires only standard local, main and default operator rules",
                ));
            }
        }
        if stage.is_some() && seen_rules.len() != expected_rules.len() {
            return Err(unsupported(
                "TUN requires all five exact rules per enabled family",
            ));
        }
        for ipv6 in spec.families() {
            let family = if ipv6 { 10 } else { 2 };
            for (priority, required) in [(0, true), (32766, true), (32767, false)] {
                let count = self
                    .rules
                    .iter()
                    .filter(|rule| rule.family == family && rule.priority == priority)
                    .count();
                if count > 1 || (required && count != 1) {
                    return Err(unsupported(
                        "TUN requires unique standard local and main rules",
                    ));
                }
            }
        }
        let mut expected_routes = if stage.is_some() {
            spec.guard_routes()
        } else {
            Vec::new()
        };
        if let (Some(index), Some(TunStage::Active)) = (ifindex, stage) {
            expected_routes.extend(spec.capture_routes(index));
        }
        let mut seen_routes = Vec::with_capacity(expected_routes.len());
        for route in &self.routes {
            if route.table == spec.table {
                let key = ifindex
                    .zip(stage)
                    .and_then(|(index, _)| self.tun_route_key(spec, route, index));
                if key.is_none_or(|key| !expected_routes.contains(&key))
                    || seen_routes.contains(&key)
                {
                    return Err(unsupported(
                        "TUN capture table contains a foreign, wrong-stage or duplicate route",
                    ));
                }
                seen_routes.push(key);
            } else if matches!(route.family, 2 | 10) && route.table == 255 {
                let own_local = route.kind == 2
                    && route.prefix_len == if route.family == 2 { 32 } else { 128 }
                    && route
                        .destination
                        .is_some_and(|destination| expected_addresses.contains(&destination));
                if route.unsupported
                    || route.flags != 0
                    || !matches!(route.kind, 2..=5)
                    || (Some(route.output) == ifindex && !own_local && !route.native_multicast)
                {
                    return Err(unsupported(
                        "TUN requires representable local routes without alternate capture paths",
                    ));
                }
            } else if matches!(route.family, 2 | 10) && matches!(route.table, 253 | 254) {
                if !self.operator_tun_route(route, ifindex) {
                    return Err(unsupported(
                        "operator main/default routes must be verifiable and avoid the TUN",
                    ));
                }
            } else if route.output != 0 && Some(route.output) == ifindex {
                return Err(unsupported("another routing table selects the owned TUN"));
            }
        }
        if stage.is_some() && seen_routes.len() != expected_routes.len() {
            return Err(unsupported(
                "TUN capture table is missing an exact guard or active route",
            ));
        }
        for ipv6 in spec.families() {
            let family = if ipv6 { 10 } else { 2 };
            if !self.routes.iter().any(|route| {
                route.family == family && route.table == 254 && route.kind == 1 && route.default
                    && self.addresses.iter().any(|address| {
                        address.family == family && address.index == route.output
                            && address.unicast_source && address.preferred && address.scope == 0
                            && address.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED | 0x20) == 0
                            && (family != 10 || !matches!(address.address, IpAddr::V6(ip) if ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some()))
                            && route.source.is_none_or(|source| source == address.address)
                    })
            }) {
                return Err(unsupported("each enabled TUN family needs a non-TUN main default and usable uplink source"));
            }
        }
        Ok(ready)
    }

    fn tun_link(&self, spec: &TunSpec<'_>, index: u32) -> bool {
        // tun_net_initialize sets POINTOPOINT|NOARP|MULTICAST; an attached,
        // administratively up queue also reports RUNNING|LOWER_UP.
        self.links.iter().any(|link| {
            link.index == index
                && interface_name(spec.name.as_bytes()).ok() == link.name
                && link.mtu == Some(spec.mtu)
                && link.kind == interface_name(b"tun").ok()
                && link.arphrd == 0xfffe
                && link.flags == 0x110d1
                && link.master == 0
        })
    }

    fn system_tun_rule(rule: &Rule) -> bool {
        !rule.unsupported
            && rule.flags == 0
            && rule.action == 1
            && rule.mark.is_none()
            && rule.mask == 0
            && rule.iif.is_none()
            && matches!(
                (rule.priority, rule.table),
                (0, 255) | (32766, 254) | (32767, 253)
            )
    }

    fn operator_tun_route(&self, route: &Route, owned: Option<u32>) -> bool {
        if route.unsupported
            || route.flags != 0
            || !matches!(route.scope, 0 | 253)
            || !matches!(route.kind, 1 | RTN_BLACKHOLE | 7 | FR_ACT_PROHIBIT | 9)
        {
            return false;
        }
        if route.kind != 1 {
            return (route.output == 0
                || (route.family == 10
                    && self
                        .links
                        .iter()
                        .any(|link| link.index == route.output && link.loopback)))
                && route.gateway.is_none()
                && route.source.is_none();
        }
        Some(route.output) != owned
            && self.links.iter().any(|link| {
                let direct_link = link.kind.is_none()
                    || [
                        b"veth".as_slice(),
                        b"bridge",
                        b"bond",
                        b"vlan",
                        b"macvlan",
                        b"ipvlan",
                        b"team",
                    ]
                    .iter()
                    .any(|kind| interface_name(kind).ok() == link.kind);
                link.index == route.output
                    && link.flags & 1 != 0
                    && !link.loopback
                    && link.master == 0
                    && direct_link
            })
            && route.source.is_none_or(|source| {
                self.addresses.iter().any(|address| {
                    address.index == route.output
                        && address.address == source
                        && address.unicast_source
                        && address.preferred
                        && address.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED | 0x20) == 0
                })
            })
    }

    fn tun_rule_key(
        &self,
        spec: &TunSpec<'_>,
        expected: &[TunRule],
        rule: &Rule,
        ifindex: u32,
        cleanup: bool,
    ) -> Option<TunRule> {
        if rule.unsupported || !matches!(rule.family, 2 | 10) {
            return None;
        }
        let name = interface_name(spec.name.as_bytes()).ok()?;
        let selector = match (rule.mark, rule.mask, rule.iif) {
            (Some(mark), u32::MAX, None) => TunRuleSelector::Fwmark(mark),
            (None, 0, Some(iif)) if iif == name => TunRuleSelector::Iif,
            (None, 0, None) => TunRuleSelector::All,
            _ => return None,
        };
        let detached = cleanup
            && selector == TunRuleSelector::Iif
            && !self
                .links
                .iter()
                .any(|link| link.index == ifindex || link.name == Some(name));
        if rule.flags != if detached { FIB_RULE_IIF_DETACHED } else { 0 } {
            return None;
        }
        if selector == TunRuleSelector::Iif && !detached && !self.tun_link(spec, ifindex) {
            return None;
        }
        let action = match (rule.action, rule.table) {
            (1, table) if table != 0 => TunRuleAction::Lookup(table),
            (FR_ACT_PROHIBIT, 0) => TunRuleAction::Prohibit,
            _ => return None,
        };
        let key = TunRule {
            ipv6: rule.family == 10,
            priority: rule.priority,
            selector,
            action,
        };
        expected.contains(&key).then_some(key)
    }

    fn tun_route_key(&self, spec: &TunSpec<'_>, route: &Route, ifindex: u32) -> Option<TunRoute> {
        if route.unsupported
            || route.protocol != RTPROT_STATIC
            || route.flags != 0
            || route.gateway.is_some()
            || route.source.is_some()
            || route.preference != 0
        {
            return None;
        }
        let kind = match route.kind {
            RTN_BLACKHOLE
                if route.scope == 0
                    && (route.output == 0
                        || (route.family == 10
                            && self
                                .links
                                .iter()
                                .any(|link| link.index == route.output && link.loopback))) =>
            {
                TunRouteKind::Blackhole
            }
            1 if ifindex != 0
                && route.output == ifindex
                && self.tun_link(spec, ifindex)
                && route.scope == if route.family == 2 { 253 } else { 0 } =>
            {
                TunRouteKind::Unicast { oif: ifindex }
            }
            _ => return None,
        };
        let key = TunRoute {
            table: route.table,
            destination: route.destination?,
            prefix_len: route.prefix_len,
            kind,
            metric: route.metric,
        };
        let metric = match kind {
            TunRouteKind::Blackhole => TUN_GUARD_METRIC,
            TunRouteKind::Unicast { .. } => TUN_CAPTURE_METRIC,
        };
        (key.table == spec.table
            && key.metric == metric
            && spec.capture.contains(&(key.destination, key.prefix_len)))
        .then_some(key)
    }

    fn tun_readback(&self, spec: &TunSpec<'_>, ifindex: u32) -> io::Result<TunReadback> {
        let expected_rules = spec.rules();
        let mut readback = TunReadback {
            link: self.links.iter().any(|link| link.index == ifindex),
            addresses: self
                .addresses
                .iter()
                .filter(|address| address.index == ifindex)
                .map(|address| (address.address, address.prefix_len))
                .collect(),
            routes: Vec::new(),
            rules: Vec::new(),
        };
        for route in self.routes.iter().filter(|route| route.table == spec.table) {
            let destination = route
                .destination
                .ok_or_else(|| malformed("unrepresentable route in TUN cleanup table"))?;
            readback.routes.push((
                route.table,
                destination,
                route.prefix_len,
                route.metric,
                self.tun_route_key(spec, route, ifindex),
            ));
        }
        for rule in self
            .rules
            .iter()
            .filter(|rule| (spec.rule_priority..=spec.rule_priority + 4).contains(&rule.priority))
        {
            if !matches!(rule.family, 2 | 10) {
                return Err(unsupported(
                    "unrepresentable rule family in TUN cleanup priority range",
                ));
            }
            readback.rules.push((
                rule.family == 10,
                rule.priority,
                self.tun_rule_key(spec, &expected_rules, rule, ifindex, true),
            ));
        }
        Ok(readback)
    }

    fn admit(
        &self,
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
    ) -> io::Result<()> {
        self.admit_with_carrier(captured_physical, captured_logical, bypass_mark, true)
    }

    fn pending_xdp_carrier(
        &self,
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
    ) -> io::Result<Option<&Link>> {
        self.admit_with_carrier(captured_physical, captured_logical, bypass_mark, false)?;
        self.ipv4_broadcasts()?;
        Ok(self
            .links
            .iter()
            .find(|link| captured_physical.contains(&link.index) && link.flags & 0x10000 == 0))
    }

    fn admit_with_carrier(
        &self,
        captured_physical: &[u32],
        captured_logical: &[u32],
        bypass_mark: u32,
        require_capture_carrier: bool,
    ) -> io::Result<()> {
        for &index in captured_physical {
            if !self.links.iter().any(|link| {
                link.index == index
                    && link.plain_up_ethernet
                    && (!require_capture_carrier || link.flags & 0x10000 != 0)
            }) {
                return Err(unsupported(
                    "capture requires unnumbered, up, standalone Ethernet roots",
                ));
            }
        }
        for &index in captured_logical {
            if !self.links.iter().any(|link| link.index == index)
                || self.addresses.iter().any(|address| address.index == index)
            {
                return Err(unsupported(
                    "logical capture interfaces must exist and remain unnumbered",
                ));
            }
        }
        if self.routes.iter().any(|route| {
            matches!(route.family, 2 | 10)
                && route.table == 255
                && !(route.native_multicast
                    || (!require_capture_carrier
                        && route.native_multicast_linkdown
                        && captured_physical.contains(&route.output)
                        && self
                            .links
                            .iter()
                            .any(|link| link.index == route.output && link.flags & 0x10000 == 0)))
                && (route.kind == 1 || captured_logical.contains(&route.output))
        }) {
            return Err(unsupported(
                "local routing table can select a captured interface",
            ));
        }
        let mut enabled = false;
        for family in [2, 10] {
            let family_enabled = self
                .addresses
                .iter()
                .any(|address| address.family == family && address.unicast_source);
            if !family_enabled {
                continue;
            }
            enabled = true;
            let mut local = 0;
            let mut mark_rule = None;
            for rule in self.rules.iter().filter(|rule| rule.family == family) {
                if !rule.simple {
                    return Err(unsupported(
                        "own-socket uplink proof rejects RPDB selectors, VRFs and rule actions",
                    ));
                }
                match rule.mark {
                    Some(mark)
                        if mark == bypass_mark
                            && rule.mask == u32::MAX
                            && rule.priority > 0
                            && rule.priority < 32766
                            && rule.table != 0
                            && !(253..=255).contains(&rule.table) =>
                    {
                        if mark_rule.replace(rule).is_some() {
                            return Err(unsupported("duplicate bypass mark rules"));
                        }
                    }
                    None if rule.mask == 0 && rule.priority == 0 && rule.table == 255 => local += 1,
                    None if rule.mask == 0
                        && ((rule.priority == 32766 && rule.table == 254)
                            || (rule.priority == 32767 && rule.table == 253)) => {}
                    _ => {
                        return Err(unsupported(
                            "RPDB is not local, exact bypass mark, then main/default",
                        ));
                    }
                }
            }
            if local != 1 {
                return Err(unsupported("missing unique priority-zero local rule"));
            }
            let rule = mark_rule.ok_or_else(|| unsupported("provision an exact bypass-mark rule before main with a dedicated uncaptured uplink table"))?;
            let mut default = false;
            for route in self
                .routes
                .iter()
                .filter(|route| route.family == family && route.table == rule.table)
            {
                if !route.simple
                    || route.kind != 1
                    || captured_logical.contains(&route.output)
                    || !self.links.iter().any(|link| {
                        link.index == route.output
                            && link.plain_up_ethernet
                            && link.flags & 0x10000 != 0
                            && !link.loopback
                    })
                {
                    return Err(unsupported(
                        "bypass table must contain only unicast routes on uncaptured standalone Ethernet uplinks",
                    ));
                }
                default |= route.default;
            }
            if !default {
                return Err(unsupported(
                    "bypass uplink table lacks a covering default for an enabled address family",
                ));
            }
        }
        if !enabled {
            return Err(unsupported("no non-loopback unicast source address family"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod tun;

    fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let length = value.len() + 4;
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
    }

    fn address_body(family: u8, index: u32, address: &[u8], local: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0; 8];
        body[0] = family;
        body[1] = if family == 2 { 32 } else { 128 };
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        attribute(&mut body, 1, address);
        if let Some(local) = local {
            attribute(&mut body, 2, local);
        }
        body
    }

    fn local_route_body(family: u8, prefix: u8, kind: u8, destination: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0; 12];
        body[0] = family;
        body[1] = prefix;
        body[4] = 255;
        body[5] = 2;
        body[7] = kind;
        if let Some(destination) = destination {
            attribute(&mut body, 1, destination);
        }
        attribute(&mut body, 4, &2u32.to_ne_bytes());
        attribute(&mut body, 6, &256u32.to_ne_bytes());
        body
    }

    #[test]
    fn native_broadcasts_require_unambiguous_local_route_authority() {
        let address = [192, 0, 2, 255];
        for (table, prefix, kind, expected) in
            [(255, 32, 3, true), (254, 32, 3, false), (255, 32, 2, false)]
        {
            let mut snapshot = topology();
            let mut body = local_route_body(2, prefix, kind, Some(&address));
            body[4] = table;
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            snapshot.push(24, &body).unwrap();
            snapshot.admit(&[2], &[2], 128).unwrap();
            let (broadcasts, count) = snapshot.ipv4_broadcasts().unwrap();
            assert_eq!(count, usize::from(expected));
            if expected {
                assert_eq!(broadcasts[0], Ipv4Addr::from(address));
            }
        }
        for mutation in 0..5 {
            let mut snapshot = topology();
            let mut body = local_route_body(2, 32, 3, Some(&address));
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            match mutation {
                0 => body[1] = 24,
                1 => body[3] = 4,
                2 => attribute(&mut body, 99, &0u32.to_ne_bytes()),
                3 => {
                    body[24..28].copy_from_slice(&2u32.to_ne_bytes());
                }
                _ => {
                    let mut conflict = local_route_body(2, 32, 2, Some(&address));
                    conflict[24..28].copy_from_slice(&3u32.to_ne_bytes());
                    snapshot.push(24, &conflict).unwrap();
                }
            }
            snapshot.push(24, &body).unwrap();
            assert!(
                snapshot
                    .admit(&[2], &[2], 128)
                    .and_then(|()| snapshot.ipv4_broadcasts().map(|_| ()))
                    .is_err()
            );
        }
        let mut canonical = topology();
        for address in [[192, 0, 9, 255], [192, 0, 2, 255], [192, 0, 9, 255]] {
            let mut body = local_route_body(2, 32, 3, Some(&address));
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            canonical.push(24, &body).unwrap();
        }
        let (addresses, count) = canonical.ipv4_broadcasts().unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            &addresses[..count],
            &[Ipv4Addr::new(192, 0, 2, 255), Ipv4Addr::new(192, 0, 9, 255)]
        );
        let mut snapshot = topology();
        for index in 0..=MAX_BROADCASTS {
            let mut body = local_route_body(2, 32, 3, Some(&[192, 0, index as u8, 255]));
            body[24..28].copy_from_slice(&3u32.to_ne_bytes());
            snapshot.push(24, &body).unwrap();
            if index < MAX_BROADCASTS {
                assert_eq!(snapshot.ipv4_broadcasts().unwrap().1, index + 1);
            }
        }
        assert!(snapshot.ipv4_broadcasts().is_err());
    }

    #[test]
    fn only_exact_simple_ipv6_multicast_routes_bypass_local_capture_refusal() {
        let multicast = Ipv6Addr::from(0xff00u128 << 112).octets();
        let unicast = "2001:db8::".parse::<Ipv6Addr>().unwrap().octets();
        let mut host_bits = multicast;
        host_bits[15] = 1;
        for (family, prefix, kind, destination, allowed) in [
            (10, 8, 5, Some(multicast.as_slice()), true),
            (10, 8, 1, Some(multicast.as_slice()), false),
            (10, 8, 2, Some(multicast.as_slice()), false),
            (10, 8, 5, Some(unicast.as_slice()), false),
            (10, 0, 5, Some(multicast.as_slice()), false),
            (10, 128, 5, Some(multicast.as_slice()), false),
            (2, 8, 5, Some(multicast.as_slice()), false),
            (10, 8, 5, Some(&multicast[..15]), false),
            (10, 8, 5, Some(host_bits.as_slice()), false),
            (10, 8, 5, None, false),
        ] {
            let mut snapshot = topology();
            snapshot
                .push(24, &local_route_body(family, prefix, kind, destination))
                .unwrap();
            assert_eq!(snapshot.routes.last().unwrap().native_multicast, allowed);
            assert_eq!(snapshot.admit(&[2], &[2], 128).is_ok(), allowed);
        }
        for mutation in 0..3 {
            let mut body = local_route_body(10, 8, 5, Some(&multicast));
            match mutation {
                0 => body[2] = 1,
                1 => body[8] = 1,
                _ => attribute(&mut body, 99, &0u32.to_ne_bytes()),
            }
            let mut snapshot = topology();
            snapshot.push(24, &body).unwrap();
            assert!(snapshot.admit(&[2], &[2], 128).is_err());
        }
        let mut duplicate = local_route_body(10, 8, 5, Some(&multicast));
        attribute(&mut duplicate, 1, &unicast);
        assert!(Snapshot::default().push(24, &duplicate).is_err());
    }

    #[test]
    fn xdp_attach_multicast_linkdown_requires_its_own_pending_physical_root() {
        let multicast = Ipv6Addr::from(0xff00u128 << 112).octets();
        let flags = std::iter::once(RTNH_F_LINKDOWN).chain((0..32).flat_map(|bit| {
            let other = 1u32 << bit;
            [other, other | RTNH_F_LINKDOWN]
        }));
        for flags in flags {
            for (root_flags, output, other_physical, allowed) in [
                (1, 2u32, false, flags == RTNH_F_LINKDOWN),
                (0x10001, 2, false, false),
                (0x10001, 2, true, false),
                (1, 4, false, false),
            ] {
                let mut current = topology();
                current.links[0].flags = root_flags;
                current.links.push(xdp_link(4, true, false));
                current.links[2].flags = 1;
                let mut body = local_route_body(10, 8, 5, Some(&multicast));
                body[8..12].copy_from_slice(&flags.to_ne_bytes());
                let output_at = body.len() - 12;
                body[output_at..output_at + 4].copy_from_slice(&output.to_ne_bytes());
                let mut cache = [0u8; 32];
                cache[0] = 1;
                cache[16] = 1;
                attribute(&mut body, 12, &cache);
                current.push(24, &body).unwrap();
                let route = current.routes.last().unwrap();
                assert!(!route.simple);
                assert!(!route.native_multicast);
                assert_eq!(route.native_multicast_linkdown, flags == RTNH_F_LINKDOWN);
                let physical = if other_physical {
                    &[2, 4][..]
                } else {
                    &[2][..]
                };
                let pending = current.pending_xdp_carrier(physical, &[2, 4], 128);
                if allowed {
                    let root = pending
                        .expect("sole LINKDOWN must not hide a pending root's multicast route")
                        .expect("attached physical root must still await carrier");
                    assert_eq!(root.index, 2);
                } else {
                    assert!(pending.is_err(), "flags={flags:#x}, output={output}");
                }
                assert!(current.admit(physical, &[2, 4], 128).is_err());
            }
        }
        let mut recovered = topology();
        recovered
            .push(24, &local_route_body(10, 8, 5, Some(&multicast)))
            .unwrap();
        assert!(recovered.admit(&[2], &[2], 128).is_ok());
    }

    #[test]
    fn xdp_attach_linkdown_preserves_multicast_shape_and_attribute_refusals() {
        let multicast = Ipv6Addr::from(0xff00u128 << 112).octets();
        let unicast = "2001:db8::".parse::<Ipv6Addr>().unwrap().octets();
        let mut host_bits = multicast;
        host_bits[15] = 1;
        for mutation in 0..16 {
            let mut current = topology();
            current.links[0].flags = 1;
            let mut body = local_route_body(10, 8, 5, Some(&multicast));
            match mutation {
                0 => body[0] = 2,
                1 => body[7] = 1,
                2 => body[1] = 128,
                3 => body = local_route_body(10, 8, 5, None),
                4 => body = local_route_body(10, 8, 5, Some(&multicast[..15])),
                5 => body = local_route_body(10, 8, 5, Some(&unicast)),
                6 => body = local_route_body(10, 8, 5, Some(&host_bits)),
                7 => body[2] = 1,
                8 => body[3] = 1,
                9 => attribute(&mut body, 99, &0u32.to_ne_bytes()),
                10 => attribute(&mut body, 8, &[]),
                11 => attribute(&mut body, 23, &[]),
                12 | 13 => {
                    let mut cache = [0u8; 32];
                    cache[if mutation == 12 { 8 } else { 12 }] = 1;
                    attribute(&mut body, 12, &cache);
                }
                14 => attribute(&mut body, 1, &multicast),
                _ => attribute(&mut body, 12, &[0; 31]),
            }
            body[8..12].copy_from_slice(&RTNH_F_LINKDOWN.to_ne_bytes());
            if let Err(error) = current.push(24, &body) {
                assert!(matches!(mutation, 14 | 15));
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                continue;
            }
            let route = current.routes.last().unwrap();
            assert!(!route.simple);
            assert!(!route.native_multicast);
            assert!(!route.native_multicast_linkdown, "mutation {mutation}");
            assert!(current.pending_xdp_carrier(&[2], &[2], 128).is_err());
        }
    }

    #[test]
    fn address_parser_classifies_actual_sources_and_prefers_local_to_peer() {
        for (text, expected) in [
            ("127.0.0.1", false),
            ("127.8.9.10", false),
            ("0.0.0.0", false),
            ("255.255.255.255", false),
            ("224.0.0.1", false),
            ("192.0.2.1", true),
            ("::1", false),
            ("::", false),
            ("ff02::1", false),
            ("2001:db8::1", true),
            ("fe80::1", true),
        ] {
            let (family, address) = match text.parse::<IpAddr>().unwrap() {
                IpAddr::V4(ip) => (2, ip.octets().to_vec()),
                IpAddr::V6(ip) => (10, ip.octets().to_vec()),
            };
            let mut snapshot = Snapshot::default();
            snapshot
                .push(20, &address_body(family, 1, &address, None))
                .unwrap();
            assert_eq!(snapshot.addresses[0].unicast_source, expected, "{text}");
        }
        for (address, local, expected) in [
            ([192, 0, 2, 1], [127, 0, 0, 1], false),
            ([127, 0, 0, 1], [192, 0, 2, 1], true),
        ] {
            let mut snapshot = Snapshot::default();
            snapshot
                .push(20, &address_body(2, 1, &address, Some(&local)))
                .unwrap();
            assert_eq!(snapshot.addresses[0].unicast_source, expected);
        }
        assert!(
            Snapshot::default()
                .push(20, &address_body(10, 1, &[0; 4], None))
                .is_err()
        );
        let mut missing = vec![0; 8];
        missing[0] = 10;
        assert!(Snapshot::default().push(20, &missing).is_err());
        let mut duplicate = address_body(2, 1, &[192, 0, 2, 1], None);
        attribute(&mut duplicate, 1, &[127, 0, 0, 1]);
        assert!(Snapshot::default().push(20, &duplicate).is_err());
    }

    #[test]
    fn global_ipv6_host_address_on_loopback_requires_ipv6_bypass_proof() {
        let mut snapshot = topology();
        snapshot.links.push(xdp_link(1, false, true));
        snapshot
            .push(20, &address_body(2, 1, &[127, 0, 0, 1], None))
            .unwrap();
        snapshot
            .push(
                20,
                &address_body(10, 1, &Ipv6Addr::LOCALHOST.octets(), None),
            )
            .unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        let global = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        snapshot
            .push(20, &address_body(10, 1, &global, None))
            .unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        let ipv6_rules: Vec<_> = snapshot
            .rules
            .iter()
            .map(|rule| Rule {
                family: 10,
                ..rule.clone()
            })
            .collect();
        snapshot.rules.extend(ipv6_rules);
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        let mut default = vec![0; 12];
        default[0] = 10;
        default[4] = 100;
        default[7] = 1;
        attribute(&mut default, 4, &3u32.to_ne_bytes());
        snapshot.push(24, &default).unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        snapshot
            .push(
                20,
                &address_body(10, 2, &Ipv6Addr::LOCALHOST.octets(), None),
            )
            .unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
    }

    #[test]
    fn rule_dump_keeps_masks_and_rejects_input_selectors() {
        let mut body = vec![0u8; 12];
        body[0] = 2;
        body[4] = 100;
        body[7] = 1;
        for (kind, value) in [(6u16, 100u32), (10, 128), (16, u32::MAX), (14, u32::MAX)] {
            body.extend_from_slice(&8u16.to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(&value.to_ne_bytes());
        }
        let mut parsed = Snapshot::default();
        parsed.push(32, &body).unwrap();
        let mut snapshot = topology();
        snapshot.rules[1] = parsed.rules.pop().unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        attribute(&mut body, 3, b"lo\0");
        parsed.push(32, &body).unwrap();
        snapshot.rules[1] = parsed.rules.pop().unwrap();
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
    }

    fn xdp_link(index: u32, plain: bool, loopback: bool) -> Link {
        let mut body = vec![0; 16];
        body[2..4].copy_from_slice(&(if plain { 1u16 } else { 0xfffe }).to_ne_bytes());
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body[8..12].copy_from_slice(&(if loopback { 9u32 } else { 0x10001 }).to_ne_bytes());
        let mut snapshot = Snapshot::default();
        snapshot.push(16, &body).unwrap();
        snapshot.links.pop().unwrap()
    }

    fn xdp_address(family: u8, index: u32) -> Address {
        let ip = if family == 2 {
            vec![192, 0, 2, 1]
        } else {
            "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec()
        };
        let mut snapshot = Snapshot::default();
        snapshot
            .push(20, &address_body(family, index, &ip, None))
            .unwrap();
        snapshot.addresses.pop().unwrap()
    }

    fn xdp_rule(family: u8, priority: u32, table: u32, mark: Option<u32>) -> Rule {
        let mut body = vec![0; 12];
        body[0] = family;
        body[7] = 1;
        attribute(&mut body, 6, &priority.to_ne_bytes());
        attribute(&mut body, 15, &table.to_ne_bytes());
        if let Some(mark) = mark {
            attribute(&mut body, 10, &mark.to_ne_bytes());
            attribute(&mut body, 16, &u32::MAX.to_ne_bytes());
        }
        let mut snapshot = Snapshot::default();
        snapshot.push(32, &body).unwrap();
        snapshot.rules.pop().unwrap()
    }

    fn xdp_route(family: u8, table: u32, output: u32, default: bool, kind: u8) -> Route {
        let mut body = vec![0; 12];
        body[0] = family;
        body[7] = kind;
        if !default {
            body[1] = if family == 2 { 24 } else { 64 };
            let destination = if family == 2 {
                vec![192, 0, 2, 0]
            } else {
                "2001:db8::".parse::<Ipv6Addr>().unwrap().octets().to_vec()
            };
            attribute(&mut body, 1, &destination);
        }
        attribute(&mut body, 15, &table.to_ne_bytes());
        attribute(&mut body, 4, &output.to_ne_bytes());
        let mut snapshot = Snapshot::default();
        snapshot.push(24, &body).unwrap();
        snapshot.routes.pop().unwrap()
    }

    fn topology() -> Snapshot {
        Snapshot {
            links: vec![xdp_link(2, true, false), xdp_link(3, true, false)],
            addresses: vec![xdp_address(2, 3)],
            rules: vec![
                xdp_rule(2, 0, 255, None),
                xdp_rule(2, 100, 100, Some(128)),
                xdp_rule(2, 32766, 254, None),
            ],
            routes: vec![
                xdp_route(2, 100, 3, true, 1),
                xdp_route(2, 254, 2, false, 1),
            ],
        }
    }

    #[test]
    fn captured_return_topology_rejects_reinjection_and_numbered_private_links() {
        let make = || {
            let mut snapshot = topology();
            let mut tap = xdp_link(4, true, false);
            let mut kind = [0u8; 16];
            kind[..3].copy_from_slice(b"tun");
            tap.kind = Some(kind);
            snapshot.links.push(tap);
            snapshot
        };
        assert!(make().captured_return(4, [2].into_iter()).is_ok());
        for mutation in 0..6 {
            let mut snapshot = make();
            match mutation {
                0 => snapshot.links.last_mut().unwrap().master = 9,
                1 => snapshot.addresses.push(xdp_address(2, 4)),
                2 => snapshot.routes.push(xdp_route(2, 254, 4, false, 1)),
                3 => snapshot.links[0].plain_up_ethernet = false,
                4 => snapshot.links.last_mut().unwrap().arphrd = 0xfffe,
                _ => snapshot.links.last_mut().unwrap().kind = None,
            }
            assert!(
                snapshot.captured_return(4, [2].into_iter()).is_err(),
                "mutation {mutation}"
            );
        }
        assert!(make().captured_return(4, [4].into_iter()).is_err());
    }

    #[test]
    fn xdp_attach_carrier_settle_preserves_strict_admission() {
        let link_body = |index: u32, flags: u32| {
            let mut body = vec![0; 16];
            body[2..4].copy_from_slice(&1u16.to_ne_bytes());
            body[4..8].copy_from_slice(&index.to_ne_bytes());
            body[8..12].copy_from_slice(&flags.to_ne_bytes());
            attribute(&mut body, 3, b"dut0\0");
            body
        };
        for flags in [1, 0x10001, 0x10000, 0] {
            let mut current = topology();
            current.push(16, &link_body(2, flags)).unwrap();
            current.links[0] = current.links.pop().unwrap();
            assert_eq!(current.admit(&[2], &[2], 128).is_ok(), flags == 0x10001);
            let pending = current.pending_xdp_carrier(&[2], &[2], 128);
            if flags & 1 == 0 {
                assert!(pending.is_err(), "admin-down roots cannot wait for carrier");
            } else if flags & 0x10000 == 0 {
                let link = pending.unwrap().expect("attached root must await carrier");
                assert_eq!(link.index, 2);
                let error = xdp_carrier_timeout(&PendingCarrier {
                    index: link.index,
                    name: link.name,
                });
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(error.to_string(), "dut0: no carrier after XDP attach");
            } else {
                assert!(pending.unwrap().is_none());
            }
        }
        for mutation in 0..7 {
            let mut current = topology();
            let mut body = link_body(2, 1);
            match mutation {
                0 => attribute(&mut body, 10, &9u32.to_ne_bytes()),
                1 => {
                    let mut info = Vec::new();
                    attribute(&mut info, 1, b"vlan\0");
                    attribute(&mut body, 18, &info);
                }
                2 => body[2..4].copy_from_slice(&0xfffeu16.to_ne_bytes()),
                3 => current.addresses.push(xdp_address(2, 2)),
                4 => {
                    current.push(16, &link_body(3, 1)).unwrap();
                    current.links[1] = current.links.pop().unwrap();
                }
                5 => current.rules[1].mask = 255,
                _ => {
                    for subnet in 0..=MAX_BROADCASTS {
                        let mut route =
                            local_route_body(2, 32, 3, Some(&[192, 0, subnet as u8, 255]));
                        route[24..28].copy_from_slice(&3u32.to_ne_bytes());
                        current.push(24, &route).unwrap();
                    }
                }
            }
            current.push(16, &body).unwrap();
            current.links[0] = current.links.pop().unwrap();
            assert!(
                current.pending_xdp_carrier(&[2], &[2], 128).is_err(),
                "non-carrier refusal {mutation} must be immediate"
            );
        }
        let mut current = topology();
        current.push(16, &link_body(4, 1)).unwrap();
        assert!(
            current
                .pending_xdp_carrier(&[2], &[2], 128)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn xdp_attach_settle_coordinator_preserves_deadline_and_failures() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(10);
        let reads = std::cell::Cell::new(0);
        let mut waited = Vec::new();
        settle_xdp_carrier(
            deadline,
            |seen| {
                assert_eq!(seen, deadline);
                let stage = reads.get();
                reads.set(stage + 1);
                let mut current = topology();
                current.links.push(xdp_link(4, true, false));
                if stage == 0 {
                    current.links[0].flags = 1;
                }
                if stage < 2 {
                    current.links[2].flags = 1;
                }
                let pending = current
                    .pending_xdp_carrier(&[2, 4], &[2, 4], 128)?
                    .map(|link| PendingCarrier {
                        index: link.index,
                        name: link.name,
                    });
                let notification = pending.as_ref().map_or(0, |link| link.index);
                Ok((notification, pending))
            },
            |notification, seen| {
                assert_eq!(seen, deadline);
                waited.push(notification);
                Ok(())
            },
            |seen| {
                assert_eq!(seen, Some(deadline));
                Ok(())
            },
            || start,
        )
        .unwrap();
        assert_eq!(waited, [2, 4]);
        assert_eq!(reads.get(), 3);

        let reads = std::cell::Cell::new(0);
        let clock = std::cell::Cell::new(start);
        let error = settle_xdp_carrier::<_, ()>(
            deadline,
            |seen| {
                assert_eq!(seen, deadline);
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    Ok((
                        (),
                        Some(PendingCarrier {
                            index: 2,
                            name: Some(interface_name(b"dut0").unwrap()),
                        }),
                    ))
                } else {
                    clock.set(deadline);
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "topology dump deadline expired",
                    ))
                }
            },
            |(), seen| {
                assert_eq!(seen, deadline);
                Ok(())
            },
            |_| panic!("expired resnapshot must not reach final admission"),
            || clock.get(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "dut0: no carrier after XDP attach");

        let error = settle_xdp_carrier::<_, ()>(
            deadline,
            |_| Ok(((), None)),
            |(), _| panic!("ready roots must not wait"),
            |seen| {
                assert_eq!(seen, Some(deadline));
                Err(unsupported("routing topology changed during admission"))
            },
            || start,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            error.to_string(),
            "routing topology changed during admission"
        );
    }

    #[test]
    fn xdp_final_admission_preserves_expired_startup_deadline() {
        let error = Topology::admit_until(&[2], &[2], 128, Some(Instant::now()))
            .err()
            .expect("expired startup must fail before opening a topology socket");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "XDP topology admission deadline expired");
    }

    #[test]
    fn marked_uplink_isolation_preserves_core_downstream_routes() {
        let mut snapshot = topology();
        assert!(snapshot.admit(&[2], &[2], 128).is_ok());
        snapshot.routes[0].output = 2;
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        snapshot.routes[0].output = 3;
        snapshot.addresses.push(xdp_address(10, 2));
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        snapshot.addresses.pop();
        snapshot.rules[1].mask = 255;
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
        snapshot.rules[1].mask = u32::MAX;
        snapshot.addresses.push(xdp_address(10, 3));
        assert!(snapshot.admit(&[2], &[2], 128).is_err());
    }

    #[test]
    fn capture_sets_require_unique_nonzero_roots_inside_logical_realm() {
        assert!(validate_capture_sets(&[2], &[4, 2], 128).is_ok());
        assert!(validate_capture_sets(&[], &[], 128).is_ok());
        let mut snapshot = topology();
        assert!(snapshot.admit(&[], &[], 128).is_ok());
        snapshot.rules[1].mask = 255;
        assert!(snapshot.admit(&[], &[], 128).is_err());
        snapshot.rules[1].mask = u32::MAX;
        snapshot.routes[0].output = 0;
        assert!(snapshot.admit(&[], &[], 128).is_err());
        assert!(validate_capture_sets(&[], &[], 0).is_err());
        assert!(validate_capture_sets(&[], &[], honk_ebpf_common::CLASSIFIED_MARK).is_err());
        for (physical, logical) in [
            (&[][..], &[2][..]),
            (&[2][..], &[][..]),
            (&[0][..], &[0][..]),
            (&[2][..], &[2, 0][..]),
            (&[2, 2][..], &[2][..]),
            (&[2][..], &[2, 2][..]),
            (&[2][..], &[4][..]),
        ] {
            assert!(validate_capture_sets(physical, logical, 128).is_err());
        }
        assert!(validate_capture_sets(&[2], &[2], 0).is_err());
        assert!(validate_capture_sets(&[2], &[2], honk_ebpf_common::CLASSIFIED_MARK).is_err());
    }

    #[test]
    fn captured_vlan_marked_routes_are_refused_regardless_of_link_shape() {
        for plain_up_ethernet in [false, true] {
            let mut snapshot = topology();
            snapshot.links.push(xdp_link(4, plain_up_ethernet, false));
            snapshot.routes[0].output = 4;
            assert!(snapshot.admit(&[2], &[2, 4], 128).is_err());
        }
    }

    #[test]
    fn external_uplink_accepts_unnumbered_captured_vlan_downstream() {
        let mut snapshot = topology();
        snapshot.links.push(xdp_link(4, false, false));
        snapshot.routes.push(xdp_route(2, 254, 4, false, 1));
        assert!(snapshot.admit(&[2], &[2, 4], 128).is_ok());
        for family in [2, 10] {
            snapshot.addresses.push(xdp_address(family, 4));
            assert!(snapshot.admit(&[2], &[2, 4], 128).is_err());
            snapshot.addresses.pop();
        }
        snapshot.routes.push(xdp_route(2, 255, 4, false, 2));
        assert!(snapshot.admit(&[2], &[2, 4], 128).is_err());
    }

    #[test]
    fn root_link_parser_distinguishes_veth_peer_from_stacked_parent() {
        for (kind, allowed) in [
            (b"veth\0".as_slice(), true),
            (b"vlan\0".as_slice(), false),
            (b"macvlan\0".as_slice(), false),
        ] {
            let mut body = vec![0; 16];
            body[2..4].copy_from_slice(&1u16.to_ne_bytes());
            body[4..8].copy_from_slice(&2u32.to_ne_bytes());
            body[8..12].copy_from_slice(&0x10001u32.to_ne_bytes());
            attribute(&mut body, 5, &9u32.to_ne_bytes());
            let mut info = Vec::new();
            attribute(&mut info, 1, kind);
            attribute(&mut body, 18, &info);
            let mut parsed = Snapshot::default();
            parsed.push(16, &body).unwrap();
            let mut snapshot = topology();
            snapshot.links[0] = parsed.links.pop().unwrap();
            assert_eq!(snapshot.admit(&[2], &[2], 128).is_ok(), allowed);
        }
    }
}
