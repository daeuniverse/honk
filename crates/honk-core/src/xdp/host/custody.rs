//! Cold plain-Host custody. Privileged topology/hook mutation is excluded by the
//! owner contract; notification delivery is not an atomic mutation fence.

use anyhow::{Context as _, ensure};
use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_link_info};
use honk_netstack::{MemoryBudget, MemoryReservation};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::ebpf::real::syscall::bpf_syscall;
use crate::netlink::NlSock;
use crate::netlink::fib::{attributes, completion_error, header, namespace_cookie};

const MAX_LINKS: usize = 256;
const MAX_RECORDS: usize = 4096;
const MAX_DATA: usize = 1 << 20;
const MAX_DATAGRAM: usize = 1 << 20;
const MAX_MESSAGES: usize = 65536;
const RTNL_GROUPS: [u32; 7] = [1, 4, 7, 8, 11, 19, 32];
type TcxBinding = (u32, u32, u32, u32);

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct Link {
    ifindex: u32,
    name: String,
    arphrd: u16,
    flags: u32,
    mtu: u32,
    address: [u8; 6],
    parent: u32,
    peer_netns: Option<i32>,
    private: bool,
    xdp: u32,
}

struct Inventory {
    links: Vec<Link>,
    records: Vec<Vec<u8>>,
    bytes: usize,
    routes: usize,
    rules: usize,
    nexthops: usize,
    qdiscs: usize,
    empty_queries: usize,
    netfilter_hooks: usize,
}

impl Inventory {
    fn new() -> Self {
        Self {
            links: Vec::with_capacity(MAX_LINKS),
            records: Vec::with_capacity(MAX_RECORDS),
            bytes: 0,
            routes: 0,
            rules: 0,
            nexthops: 0,
            qdiscs: 0,
            empty_queries: 0,
            netfilter_hooks: 0,
        }
    }

    fn record(&mut self, kind: u16, payload: &[u8]) -> io::Result<()> {
        let bytes = payload
            .len()
            .checked_add(2)
            .ok_or_else(|| invalid("custody record overflow"))?;
        if self.records.len() == MAX_RECORDS || bytes > MAX_DATA - self.bytes {
            return Err(invalid("Host custody inventory exceeds cold storage bound"));
        }
        let mut record = Vec::with_capacity(bytes);
        record.extend_from_slice(&kind.to_ne_bytes());
        record.extend_from_slice(payload);
        self.records.push(record);
        self.bytes += bytes;
        Ok(())
    }

    fn record_owned(&mut self, record: Vec<u8>) -> io::Result<()> {
        if self.records.len() == MAX_RECORDS || record.len() > MAX_DATA - self.bytes {
            return Err(invalid("Host custody inventory exceeds cold storage bound"));
        }
        self.bytes += record.len();
        self.records.push(record);
        Ok(())
    }

    fn record_hook(&mut self, family: u8, hook: u32, active: bool, body: &[u8]) -> io::Result<()> {
        if !active
            || !matches!(family, 2 | 10)
            || hook != 4
            || body.get(..4) != Some(&[family, 0, 0, 0])
        {
            return Err(invalid(
                "Host hook lacks active AppArmor POSTROUTING identity",
            ));
        }
        let mut seen = 0u8;
        let mut bytes = &body[4..];
        while !bytes.is_empty() {
            if bytes.len() < 4 {
                return Err(invalid("short Host hook attribute"));
            }
            let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap());
            if length < 4 || length.next_multiple_of(4) > bytes.len() {
                return Err(invalid("truncated Host hook attribute"));
            }
            let value = &bytes[4..length];
            // nfnetlink_hook.c derives this symbol from ops->hook via %ps.
            // It is kernel symbol provenance, not offset/code attestation.
            let bit = match kind {
                1 if value == 4u32.to_be_bytes() => 1,
                2 if value == (-225i32).to_be_bytes() => 2,
                4 if value == b"apparmor_ip_postroute\0" => 4,
                _ => return Err(invalid("foreign/unsupported Host netfilter hook")),
            };
            if seen & bit != 0 {
                return Err(invalid("duplicate Host hook attribute"));
            }
            seen |= bit;
            bytes = &bytes[length.next_multiple_of(4)..];
        }
        if seen != 7
            || self.records.iter().any(|record| {
                record.get(..2) == Some(&0x0c00u16.to_ne_bytes()) && record.get(2) == Some(&family)
            })
        {
            return Err(invalid("incomplete/duplicate Host AppArmor hook"));
        }
        self.record(0x0c00, body)?;
        self.netfilter_hooks += 1;
        Ok(())
    }

    fn seal(&mut self) -> io::Result<()> {
        self.links.sort_unstable_by_key(|link| link.ifindex);
        if self
            .links
            .windows(2)
            .any(|pair| pair[0].ifindex == pair[1].ifindex)
        {
            return Err(invalid("duplicate Host namespace link identity"));
        }
        self.records.sort_unstable();
        Ok(())
    }
}

struct Channels {
    route: NlSock,
    xfrm: NlSock,
    netfilter: NlSock,
    receive: Vec<u8>,
}

pub(crate) struct CustodySnapshot {
    namespace: OwnedFd,
    namespace_device: u64,
    namespace_inode: u64,
    namespace_cookie: u64,
    monitor: OwnedFd,
    channels: Mutex<Channels>,
    inventory: Inventory,
    private_pair: [u32; 2],
    selected: Vec<u32>,
    tcx: Vec<TcxBinding>,
    tcx_fds: Vec<OwnedFd>,
    xdp: Vec<(u32, u32)>,
    owned_programs: Vec<u32>,
    _charge: MemoryReservation,
}

impl CustodySnapshot {
    /// The caller enters the supplied namespace for cold capture. All later
    /// netlink operations use these retained namespace-bound sockets.
    pub(super) fn capture(
        namespace_fd: BorrowedFd<'_>,
        owned_program_ids: &[u32],
        private_pair: [u32; 2],
        selected_ifindices: &[u32],
        expected_tcx: &[TcxBinding],
        expected_xdp: &[(u32, u32)],
        budget: &Arc<MemoryBudget>,
    ) -> anyhow::Result<Self> {
        ensure!(
            selected_ifindices.len() <= MAX_LINKS
                && expected_tcx.len() <= 2 * MAX_LINKS
                && expected_xdp.len() <= 2 * MAX_LINKS
                && owned_program_ids.len() <= 2 * MAX_LINKS,
            "Host custody ownership input exceeds bounds"
        );
        ensure!(
            selected_ifindices.iter().all(|index| *index != 0),
            "zero selected Host device"
        );
        ensure!(
            private_pair.iter().filter(|&&index| index != 0).count() == 1,
            "Host custody needs its owned private endpoint"
        );
        for (at, binding) in expected_tcx.iter().enumerate() {
            ensure!(
                binding.0 != 0
                    && matches!(binding.1, 46 | 47)
                    && binding.2 != 0
                    && binding.3 != 0
                    && owned_program_ids.contains(&binding.2)
                    && !expected_tcx[..at]
                        .iter()
                        .any(|other| other.0 == binding.0 && other.1 == binding.1),
                "invalid or duplicate Host TCX ownership binding"
            );
        }
        for (at, &(index, program)) in expected_xdp.iter().enumerate() {
            let variants = expected_xdp
                .iter()
                .filter(|binding| binding.0 == index)
                .count();
            ensure!(
                index != 0
                    && program != 0
                    && owned_program_ids.contains(&program)
                    && !expected_xdp[..at].contains(&(index, program))
                    && variants <= if private_pair[0] != 0 { 2 } else { 1 },
                "invalid or duplicate Host XDP ownership binding"
            );
        }
        // Includes two inventories, dump scratch, and the bounded JSON receipt's
        // hex strings/value cells while the owner serializes it.
        let bytes = 6 * MAX_DATA
            + 4 * MAX_RECORDS * size_of::<Vec<u8>>()
            + 8 * MAX_LINKS * (size_of::<Link>() + 128)
            + size_of::<Self>();
        let charge = budget
            .reserve(bytes)
            .context("Host custody cold memory budget exhausted")?;
        let namespace = namespace_fd.try_clone_to_owned()?;
        let stat = nix::sys::stat::fstat(&namespace)?;
        let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
        ensure!(
            current.dev() == stat.st_dev && current.ino() == stat.st_ino,
            "Host custody capture is outside its pinned namespace"
        );
        let route = NlSock::new().context("Host custody NETLINK_ROUTE")?;
        let cookie = namespace_cookie(route.fd.as_raw_fd())?;
        let monitor = NlSock::new().context("Host custody RTNL monitor")?.fd;
        for group in RTNL_GROUPS {
            // SAFETY: setsockopt borrows an initialized group ID for this call.
            let result = unsafe {
                libc::setsockopt(
                    monitor.as_raw_fd(),
                    libc::SOL_NETLINK,
                    libc::NETLINK_ADD_MEMBERSHIP,
                    (&group as *const u32).cast(),
                    size_of::<u32>() as _,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error()).context("Host RTNL membership");
            }
        }
        // SAFETY: this descriptor is uniquely owned and F_SETFL changes no lifetime.
        ensure!(
            unsafe { libc::fcntl(monitor.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } >= 0,
            "Host RTNL monitor nonblocking: {}",
            io::Error::last_os_error()
        );
        let mut channels = Channels {
            route,
            xfrm: NlSock::from_protocol(libc::NETLINK_XFRM)
                .context("Host custody NETLINK_XFRM unavailable")?,
            netfilter: NlSock::from_protocol(libc::NETLINK_NETFILTER)
                .context("Host custody NETLINK_NETFILTER unavailable")?,
            receive: vec![0; MAX_DATAGRAM],
        };
        let mut inventory = channels.inventory(private_pair, selected_ifindices, expected_xdp)?;
        for link in &inventory.links {
            check_tcx(link.ifindex, expected_tcx)?;
        }
        for binding in expected_tcx {
            ensure!(
                inventory.links.iter().any(|link| link.ifindex == binding.0),
                "owned Host TCX device is absent from namespace"
            );
        }
        let mut tcx_fds = Vec::with_capacity(expected_tcx.len());
        for binding in expected_tcx {
            let fd = link_fd(binding.3)?;
            check_link(fd.as_fd(), *binding)?;
            tcx_fds.push(fd);
        }
        inventory.seal()?;
        monitor_quiet(monitor.as_fd())?;
        Ok(Self {
            namespace,
            namespace_device: stat.st_dev,
            namespace_inode: stat.st_ino,
            namespace_cookie: cookie,
            monitor,
            channels: Mutex::new(channels),
            inventory,
            private_pair,
            selected: selected_ifindices.to_vec(),
            tcx: expected_tcx.to_vec(),
            tcx_fds,
            xdp: expected_xdp.to_vec(),
            owned_programs: owned_program_ids.to_vec(),
            _charge: charge,
        })
    }

    pub(crate) fn revalidate(&self) -> anyhow::Result<()> {
        if !monitor_pending(self.monitor.as_fd())? {
            return Ok(());
        }
        let stat = nix::sys::stat::fstat(&self.namespace)?;
        ensure!(
            stat.st_dev == self.namespace_device && stat.st_ino == self.namespace_inode,
            "Host custody namespace identity changed"
        );
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| anyhow::anyhow!("Host custody query lock poisoned"))?;
        ensure!(
            namespace_cookie(channels.route.fd.as_raw_fd())? == self.namespace_cookie,
            "Host custody RTNL namespace cookie changed"
        );
        drain_notifications(self.monitor.as_fd(), &mut channels.receive, |kind, _| {
            if !matches!(
                kind,
                16 | 17
                    | 20
                    | 21
                    | 24
                    | 25
                    | 28
                    | 29
                    | 32
                    | 33
                    | 36
                    | 37
                    | 40
                    | 41
                    | 44
                    | 45
                    | 48
                    | 49
                    | 80
                    | 81
                    | 104
                    | 105
            ) {
                return Err(invalid("unsupported Host custody dependency notification"));
            }
            Ok(())
        })?;
        let mut current = channels.inventory(self.private_pair, &self.selected, &self.xdp)?;
        current.seal()?;
        for (before, after) in self.inventory.links.iter().zip(&mut current.links) {
            if before.ifindex == after.ifindex
                && self.xdp.contains(&(before.ifindex, before.xdp))
                && self.xdp.contains(&(after.ifindex, after.xdp))
            {
                after.xdp = before.xdp;
            }
        }
        ensure!(
            current.links == self.inventory.links && current.records == self.inventory.records,
            "Host namespace custody inventory changed"
        );
        for (&binding, fd) in self.tcx.iter().zip(&self.tcx_fds) {
            check_link(fd.as_fd(), binding)?;
        }
        // TCX queries have no namespace-FD target. Source runtime remains in the
        // source namespace; child cross-namespace revalidation is RTNL/XDP only.
        let current_namespace = File::open("/proc/thread-self/ns/net")?.metadata()?;
        if current_namespace.dev() == self.namespace_device
            && current_namespace.ino() == self.namespace_inode
        {
            for link in &self.inventory.links {
                check_tcx(link.ifindex, &self.tcx)?;
            }
        } else {
            ensure!(
                self.private_pair[0] == 0 && self.tcx.is_empty(),
                "Host source TCX revalidation left its pinned namespace"
            );
        }
        monitor_quiet(self.monitor.as_fd())?;
        Ok(())
    }

    pub(super) fn acknowledge_xdp(
        &mut self,
        ifindex: u32,
        old: u32,
        new: u32,
    ) -> anyhow::Result<()> {
        ensure!(
            self.private_pair[1] == ifindex
                && old != 0
                && new != 0
                && old != new
                && self.owned_programs.contains(&new),
            "Host XDP acknowledgement is not an owned private child transition"
        );
        let current_namespace = File::open("/proc/thread-self/ns/net")?.metadata()?;
        ensure!(
            current_namespace.dev() == self.namespace_device
                && current_namespace.ino() == self.namespace_inode,
            "Host XDP acknowledgement left its pinned child namespace"
        );
        let slot = self
            .xdp
            .iter()
            .position(|binding| *binding == (ifindex, old))
            .context("Host XDP acknowledgement does not match owned old program")?;
        let mut expected = self.xdp.clone();
        expected[slot].1 = new;
        let mut channels = self
            .channels
            .lock()
            .map_err(|_| anyhow::anyhow!("Host custody query lock poisoned"))?;
        let before = self
            .inventory
            .links
            .iter()
            .find(|link| link.ifindex == ifindex)
            .context("Host XDP acknowledgement lost its private link")?;
        drain_notifications(self.monitor.as_fd(), &mut channels.receive, |kind, body| {
            if kind != 16 {
                return Err(invalid(
                    "foreign notification during Host XDP acknowledgement",
                ));
            }
            let mut link = parse_link(body, self.private_pair, &expected)?;
            link.xdp = old;
            if &link != before {
                return Err(invalid(
                    "foreign link mutation during Host XDP acknowledgement",
                ));
            }
            Ok(())
        })?;
        let mut current = channels.inventory(self.private_pair, &self.selected, &expected)?;
        current.seal()?;
        ensure!(
            current.records == self.inventory.records
                && current.links.len() == self.inventory.links.len(),
            "Host namespace changed during owned XDP transition"
        );
        for (before, after) in self.inventory.links.iter().zip(&mut current.links) {
            if before.ifindex == ifindex {
                ensure!(
                    before.xdp == old && after.xdp == new,
                    "Host private XDP transition has unexpected program IDs"
                );
                after.xdp = old;
                ensure!(
                    before == after,
                    "Host private link changed during XDP transition"
                );
                after.xdp = new;
            } else {
                ensure!(
                    before == after,
                    "foreign Host link changed during XDP transition"
                );
            }
            check_tcx(after.ifindex, &self.tcx)?;
        }
        monitor_quiet(self.monitor.as_fd())?;
        self.xdp = expected;
        self.inventory = current;
        Ok(())
    }

    pub(crate) fn evidence(&self) -> serde_json::Value {
        let records: Vec<String> = self
            .inventory
            .records
            .iter()
            .map(|record| {
                use std::fmt::Write as _;
                let mut value = String::with_capacity(record.len() * 2);
                for byte in record {
                    let _ = write!(value, "{byte:02x}");
                }
                value
            })
            .collect();
        serde_json::json!({
            "namespace_device": self.namespace_device,
            "namespace_inode": self.namespace_inode,
            "namespace_cookie": self.namespace_cookie,
            "private_pair": self.private_pair,
            "selected_ifindices": self.selected,
            "links": self.inventory.links,
            "tcx_bindings": self.tcx,
            "xdp_bindings": self.xdp,
            "routes": self.inventory.routes,
            "rules": self.inventory.rules,
            "nexthops": self.inventory.nexthops,
            "qdiscs": self.inventory.qdiscs,
            "completed_empty_queries": self.inventory.empty_queries,
            "immutable_records_hex": records,
            "xfrm_states": 0,
            "xfrm_policies": 0,
            "nftables_tables": 0,
            "netfilter_hooks": self.inventory.netfilter_hooks,
            "legacy_tc_filters": 0,
            "privileged_mutation_excluded": true,
            "notification_atomic_fence": false,
            "cross_namespace_tcx_revalidation": false
        })
    }
}

impl AsFd for CustodySnapshot {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.monitor.as_fd()
    }
}

impl Channels {
    fn inventory(
        &mut self,
        private_pair: [u32; 2],
        selected: &[u32],
        xdp: &[(u32, u32)],
    ) -> anyhow::Result<Inventory> {
        let mut inventory = Inventory::new();
        dump(
            &mut self.route,
            &mut self.receive,
            18,
            16,
            &[0; 16],
            |body| {
                if inventory.links.len() == MAX_LINKS {
                    return Err(invalid("Host namespace link limit exceeded"));
                }
                inventory.links.push(parse_link(body, private_pair, xdp)?);
                Ok(())
            },
        )
        .context("Host namespace-wide RTM_GETLINK custody")?;
        for index in selected
            .iter()
            .chain(private_pair.iter().filter(|index| **index != 0))
        {
            ensure!(
                inventory.links.iter().any(|link| link.ifindex == *index),
                "Host selected/private device missing from namespace"
            );
        }
        for (index, _) in xdp {
            ensure!(
                inventory.links.iter().any(|link| link.ifindex == *index),
                "owned Host XDP device missing from namespace"
            );
        }
        dump(
            &mut self.route,
            &mut self.receive,
            26,
            24,
            &[0; 12],
            |body| {
                let record = plain_route(body, &inventory.links)?;
                inventory.record_owned(record)?;
                inventory.routes += 1;
                Ok(())
            },
        )
        .context("Host all-table RTM_GETROUTE custody")?;
        // AF_UNSPEC also enumerates multicast-router rules, not local IP output.
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let mut request = [0; 12];
            request[0] = family;
            dump(
                &mut self.route,
                &mut self.receive,
                34,
                32,
                &request,
                |body| {
                    plain_rule(body)?;
                    inventory.record(32, body)?;
                    inventory.rules += 1;
                    Ok(())
                },
            )
            .context("Host IPv4/IPv6 RTM_GETRULE custody")?;
        }
        dump(
            &mut self.route,
            &mut self.receive,
            106,
            104,
            &[0; 8],
            |body| {
                plain_nexthop(body, &inventory.links)?;
                inventory.record(104, body)?;
                inventory.nexthops += 1;
                Ok(())
            },
        )
        .context("Host all-nexthop RTM_GETNEXTHOP custody")?;
        dump(
            &mut self.route,
            &mut self.receive,
            38,
            36,
            &[0; 20],
            |body| {
                let record = plain_qdisc(body, &inventory.links)?;
                inventory.record_owned(record)?;
                inventory.qdiscs += 1;
                Ok(())
            },
        )
        .context("Host namespace-wide RTM_GETQDISC custody")?;
        for link in &inventory.links {
            // Only classless built-in schedulers and clsact/ingress are admitted.
            // Every chain at each possible filter block must actually dump empty.
            for parent in [0u32, 0xffff_fff1, 0xffff_fff2, 0xffff_fff3] {
                let mut body = [0; 20];
                body[4..8].copy_from_slice(&link.ifindex.to_ne_bytes());
                body[12..16].copy_from_slice(&parent.to_ne_bytes());
                empty_dump(&mut self.route, &mut self.receive, 46, 44, &body).with_context(
                    || {
                        format!(
                            "Host legacy TC filter/action custody on {} parent {parent:#x}",
                            link.name
                        )
                    },
                )?;
                inventory.empty_queries += 1;
            }
        }
        empty_dump(&mut self.xfrm, &mut self.receive, 18, 16, &[])
            .context("Host XFRM_MSG_GETSA must complete empty")?;
        empty_dump(&mut self.xfrm, &mut self.receive, 21, 19, &[])
            .context("Host XFRM_MSG_GETPOLICY must complete empty")?;
        inventory.empty_queries += 2;
        empty_dump(
            &mut self.netfilter,
            &mut self.receive,
            0x0a01,
            0x0a00,
            &[0; 4],
        )
        .context("Host NFT_MSG_GETTABLE must complete empty for every family")?;
        inventory.empty_queries += 1;
        let active = super::object::Object::active_lsm()?;
        let apparmor = active.trim().split(',').any(|name| name == "apparmor");
        for (family, hooks) in [(2, 5), (10, 5), (3, 3), (7, 5)] {
            for hook in 0..hooks {
                if matches!(family, 2 | 10) && hook == 4 {
                    self.apparmor_hook(family, apparmor, &mut inventory)?;
                } else {
                    self.empty_hook(family, hook, None)?;
                    inventory.empty_queries += 1;
                }
            }
        }
        for link in &inventory.links {
            for hook in 0..2 {
                self.empty_hook(5, hook, Some(&link.name))?;
                inventory.empty_queries += 1;
            }
        }
        Ok(inventory)
    }

    fn empty_hook(&mut self, family: u8, hook: u32, device: Option<&str>) -> anyhow::Result<()> {
        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&[family, 0, 0, 0]);
        put_attribute(&mut body, 1 | 0x4000, &hook.to_be_bytes());
        if let Some(name) = device {
            let mut terminated = [0; libc::IFNAMSIZ];
            ensure!(
                name.len() < terminated.len(),
                "Host netfilter device name exceeds IFNAMSIZ"
            );
            terminated[..name.len()].copy_from_slice(name.as_bytes());
            put_attribute(&mut body, 3, &terminated[..name.len() + 1]);
        }
        empty_dump(&mut self.netfilter, &mut self.receive, 0x0c00, 0x0c00, &body)
            .with_context(|| format!("Host NFNL_SUBSYS_HOOK GET family {family} hook {hook} device {device:?} must complete empty"))
    }

    fn apparmor_hook(
        &mut self,
        family: u8,
        active: bool,
        inventory: &mut Inventory,
    ) -> anyhow::Result<()> {
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&[family, 0, 0, 0]);
        put_attribute(&mut body, 1 | 0x4000, &4u32.to_be_bytes());
        let before = inventory.netfilter_hooks;
        dump(
            &mut self.netfilter,
            &mut self.receive,
            0x0c00,
            0x0c00,
            &body,
            |record| inventory.record_hook(family, 4, active, record),
        )
        .with_context(|| {
            format!("Host NFNL_SUBSYS_HOOK GET family {family} POSTROUTING custody")
        })?;
        if inventory.netfilter_hooks == before {
            inventory.empty_queries += 1;
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32_value(bytes: &[u8]) -> io::Result<u32> {
    bytes
        .try_into()
        .map(u32::from_ne_bytes)
        .map_err(|_| invalid("invalid Host custody u32 attribute"))
}
fn string(bytes: &[u8]) -> io::Result<&str> {
    let value = bytes
        .strip_suffix(&[0])
        .ok_or_else(|| invalid("unterminated Host netlink string"))?;
    if value.contains(&0) {
        return Err(invalid("embedded NUL in Host netlink string"));
    }
    std::str::from_utf8(value).map_err(|_| invalid("non-UTF8 Host netlink string"))
}
fn put_attribute(buffer: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = value.len() + 4;
    buffer.extend_from_slice(&(length as u16).to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(value);
    buffer.resize(buffer.len() + length.next_multiple_of(4) - length, 0);
}

fn parse_link(body: &[u8], pair: [u32; 2], expected_xdp: &[(u32, u32)]) -> io::Result<Link> {
    if body.len() < 16 {
        return Err(invalid("short Host ifinfomsg"));
    }
    let ifindex = u32_value(&body[4..8])?;
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(invalid("invalid Host ifindex"));
    }
    let arphrd = u16::from_ne_bytes(body[2..4].try_into().unwrap());
    let private = pair.contains(&ifindex);
    let mut link = Link {
        ifindex,
        name: String::new(),
        arphrd,
        flags: u32_value(&body[8..12])?,
        mtu: 0,
        address: [0; 6],
        parent: 0,
        peer_netns: None,
        private,
        xdp: 0,
    };
    let mut kind = None;
    let mut address_seen = false;
    let mut xdp_seen = false;
    attributes(&body[16..], |attribute, value| {
        match attribute {
            1 => {
                link.address = value
                    .try_into()
                    .map_err(|_| invalid("Host link is not Ethernet/loopback"))?;
                address_seen = true;
            }
            3 => {
                let name = string(value)?;
                if name.is_empty() || name.len() >= libc::IFNAMSIZ {
                    return Err(invalid("invalid Host link name"));
                }
                link.name = name.to_owned();
            }
            4 => link.mtu = u32_value(value)?,
            5 => link.parent = u32_value(value)?,
            10 if u32_value(value)? != 0 => {
                return Err(invalid("Host namespace contains a mastered link"));
            }
            18 => attributes(value, |nested, data| {
                match nested {
                    1 => kind = Some(string(data)?),
                    2 if private => {}
                    3 => {}
                    _ => {
                        return Err(invalid(
                            "Host namespace contains a slave/unsupported link stack",
                        ));
                    }
                }
                Ok(())
            })?,
            37 => link.peer_netns = Some(u32_value(value)? as i32),
            43 => {
                xdp_seen = true;
                link.xdp = plain_xdp(value)?;
            }
            _ => {}
        }
        Ok(())
    })?;
    if !address_seen || !xdp_seen || link.name.is_empty() || link.mtu == 0 {
        return Err(invalid("incomplete Host link identity/XDP readback"));
    }
    if private {
        if arphrd != 1 || kind != Some("veth") || link.parent == 0 || link.peer_netns.is_none() {
            return Err(invalid(
                "Host private endpoint is not a cross-namespace veth",
            ));
        }
    } else if !matches!(arphrd, 1 | 772)
        || kind.is_some()
        || link.peer_netns.is_some()
        || (link.parent != 0 && link.parent != ifindex)
    {
        return Err(invalid(
            "Host namespace contains a non-plain output/lower/tunnel link",
        ));
    }
    if arphrd == 772 && link.flags & libc::IFF_LOOPBACK as u32 == 0 {
        return Err(invalid("Host loopback lacks loopback identity"));
    }
    let expected = expected_xdp.iter().any(|binding| binding.0 == ifindex);
    if (expected && !expected_xdp.contains(&(ifindex, link.xdp))) || (!expected && link.xdp != 0) {
        return Err(invalid(
            "Host namespace has foreign or missing XDP attachment",
        ));
    }
    Ok(link)
}

fn plain_xdp(bytes: &[u8]) -> io::Result<u32> {
    let mut attached = None;
    let mut id = 0;
    let mut driver = 0;
    attributes(bytes, |kind, value| {
        match kind {
            2 if value.len() == 1 => attached = Some(value[0]),
            4 => id = u32_value(value)?,
            5 => driver = u32_value(value)?,
            6 | 7 if u32_value(value)? == 0 => {}
            _ => return Err(invalid("unsupported Host XDP attachment composition")),
        }
        Ok(())
    })?;
    match attached {
        Some(0) if id == 0 && driver == 0 => Ok(0),
        Some(1) if id != 0 && (driver == 0 || driver == id) => Ok(id),
        _ => Err(invalid(
            "Host requires no XDP or one exact native XDP program",
        )),
    }
}

fn known_output(index: u32, links: &[Link]) -> io::Result<()> {
    if index == 0 || !links.iter().any(|link| link.ifindex == index) {
        return Err(invalid(
            "Host route/nexthop references an uninspected output device",
        ));
    }
    Ok(())
}

fn route_attributes(bytes: &[u8], links: &[Link]) -> io::Result<()> {
    attributes(bytes, |kind, value| {
        match kind {
            3 | 4 => known_output(u32_value(value)?, links)?,
            8 => attributes(value, |metric, data| {
                if !(1..=17).contains(&metric) || data.is_empty() {
                    return Err(invalid("unsupported Host route metric"));
                }
                Ok(())
            })?,
            9 => {
                let mut remaining = value;
                while !remaining.is_empty() {
                    if remaining.len() < 8 {
                        return Err(invalid("short Host multipath nexthop"));
                    }
                    let len = u16::from_ne_bytes(remaining[..2].try_into().unwrap()) as usize;
                    if len < 8 || len.next_multiple_of(4) > remaining.len() {
                        return Err(invalid("malformed Host multipath nexthop"));
                    }
                    known_output(u32_value(&remaining[4..8])?, links)?;
                    attributes(&remaining[8..len], |nested, data| {
                        if nested != 5 || !matches!(data.len(), 4 | 16) {
                            return Err(invalid(
                                "Host multipath contains transform/unsupported path",
                            ));
                        }
                        Ok(())
                    })?;
                    remaining = &remaining[len.next_multiple_of(4)..];
                }
            }
            1 | 2 | 5 | 6 | 7 | 11 | 12 | 15 | 16 | 20 | 24 | 25 | 26 | 27 | 28 | 29 | 30 => {}
            _ => {
                return Err(invalid(
                    "Host route contains LWT/encapsulation/unsupported attributes",
                ));
            }
        }
        Ok(())
    })
}

fn plain_route(body: &[u8], links: &[Link]) -> io::Result<Vec<u8>> {
    if body.len() < 12 || !matches!(body[0], 2 | 10) || !matches!(body[7], 1..=9) {
        return Err(invalid(
            "Host route family/type can transform or lacks custody",
        ));
    }
    route_attributes(&body[12..], links)?;
    let mut record = Vec::with_capacity(body.len() + 2);
    record.extend_from_slice(&24u16.to_ne_bytes());
    record.extend_from_slice(&body[..12]);
    attributes(&body[12..], |kind, value| {
        // rta_cacheinfo is elapsed use/expiry accounting, not route identity.
        if kind != 12 {
            put_attribute(&mut record, kind, value);
        }
        Ok(())
    })?;
    Ok(record)
}

fn plain_rule(body: &[u8]) -> io::Result<()> {
    if body.len() < 12 || !matches!(body[0], 2 | 10) || !matches!(body[7], 1 | 2 | 3 | 6 | 7 | 8) {
        return Err(invalid("unsupported Host RPDB family/action"));
    }
    attributes(&body[12..], |kind, value| {
        if !matches!(kind, 1..=4 | 6 | 10 | 11 | 13..=18 | 20..=25) {
            return Err(invalid("Host RPDB contains tunnel/l3mdev/unknown selector"));
        }
        if matches!(kind, 3 | 17) {
            string(value)?;
        }
        Ok(())
    })
}

fn plain_nexthop(body: &[u8], links: &[Link]) -> io::Result<()> {
    if body.len() < 8 || !matches!(body[0], 0 | 2 | 10) {
        return Err(invalid("unsupported Host nexthop family"));
    }
    let mut id = false;
    let mut target = false;
    attributes(&body[8..], |kind, value| {
        match kind {
            1 => id = u32_value(value)? != 0,
            4 if value.is_empty() => target = true,
            5 => {
                known_output(u32_value(value)?, links)?;
                target = true;
            }
            6 if matches!(value.len(), 4 | 16) => {}
            _ => return Err(invalid("Host nexthop group/encapsulation/unsupported path")),
        }
        Ok(())
    })?;
    if !id || !target {
        return Err(invalid("incomplete Host nexthop identity"));
    }
    Ok(())
}

fn plain_qdisc(body: &[u8], links: &[Link]) -> io::Result<Vec<u8>> {
    if body.len() < 20 {
        return Err(invalid("short Host qdisc identity"));
    }
    known_output(u32_value(&body[4..8])?, links)?;
    let mut kind = None;
    let mut record = Vec::with_capacity(body.len() + 2);
    record.extend_from_slice(&36u16.to_ne_bytes());
    record.extend_from_slice(&body[..20]);
    attributes(&body[20..], |attribute, value| {
        match attribute {
            1 => {
                kind = Some(string(value)?);
                put_attribute(&mut record, attribute, value);
            }
            2 | 8 | 13 | 14 => {
                if matches!(attribute, 13 | 14) && u32_value(value)? != 0 {
                    return Err(invalid("Host qdisc references foreign shared filter block"));
                }
                put_attribute(&mut record, attribute, value);
            }
            3..=7 | 9 | 12 => {}
            _ => return Err(invalid("unsupported Host qdisc attribute")),
        }
        Ok(())
    })?;
    if !matches!(
        kind,
        Some(
            "noqueue"
                | "mq"
                | "pfifo"
                | "bfifo"
                | "pfifo_fast"
                | "fq"
                | "fq_codel"
                | "clsact"
                | "ingress"
        )
    ) {
        return Err(invalid(
            "Host qdisc may classify/transform/reinject packets",
        ));
    }
    Ok(record)
}

fn dump(
    socket: &mut NlSock,
    receive: &mut Vec<u8>,
    request_type: u16,
    response_type: u16,
    body: &[u8],
    mut visit: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    socket.seq = socket
        .seq
        .checked_add(1)
        .ok_or_else(|| invalid("Host custody netlink sequence exhausted"))?;
    let sequence = socket.seq;
    let mut request = Vec::with_capacity(body.len() + 16);
    request.extend_from_slice(&((body.len() + 16) as u32).to_ne_bytes());
    request.extend_from_slice(&request_type.to_ne_bytes());
    request.extend_from_slice(&0x301u16.to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(body);
    socket.send_datagram(&request)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut messages = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let length = socket.recv_one(receive)?;
        let mut bytes = &receive[..length];
        let mut completed = false;
        while !bytes.is_empty() {
            messages += 1;
            if messages > MAX_MESSAGES {
                return Err(invalid("Host custody netlink dump message bound"));
            }
            let (len, kind, flags, seq) = header(bytes)?;
            if seq != sequence || completed || flags & 0x10 != 0 {
                return Err(invalid("interrupted/mismatched Host custody netlink dump"));
            }
            let payload = &bytes[16..len];
            if matches!(kind, 2 | 3) {
                let errno = completion_error(kind, flags, payload, &request, true)?;
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                completed = true;
            } else if kind == response_type {
                visit(payload)?;
            } else {
                return Err(invalid("unexpected Host custody netlink reply"));
            }
            bytes = &bytes[len.next_multiple_of(4)..];
        }
        if completed {
            return Ok(());
        }
    }
}

fn empty_dump(
    socket: &mut NlSock,
    receive: &mut Vec<u8>,
    request_type: u16,
    response_type: u16,
    body: &[u8],
) -> io::Result<()> {
    dump(socket, receive, request_type, response_type, body, |_| {
        Err(invalid("foreign/nonempty Host custody composition"))
    })
}

fn drain_notifications(
    fd: BorrowedFd<'_>,
    receive: &mut [u8],
    mut visit: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    for _ in 0..MAX_MESSAGES {
        // SAFETY: recvmsg writes only into the initialized receive/address buffers.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: receive.as_mut_ptr().cast(),
            iov_len: receive.len(),
        };
        message.msg_name = (&mut source as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = size_of::<libc::sockaddr_nl>() as _;
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        let length = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
        if length < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(())
            } else {
                Err(error)
            };
        }
        if length == 0
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || source.nl_pid != 0
            || message.msg_namelen as usize != size_of::<libc::sockaddr_nl>()
        {
            return Err(invalid("lost/non-kernel Host custody notification"));
        }
        let mut bytes = &receive[..length as usize];
        while !bytes.is_empty() {
            let (len, kind, flags, _) = header(bytes)?;
            if flags & 0x10 != 0 {
                return Err(invalid("interrupted Host custody notification"));
            }
            visit(kind, &bytes[16..len])?;
            bytes = &bytes[len.next_multiple_of(4)..];
        }
    }
    Err(invalid("Host custody notification bound exceeded"))
}

fn monitor_pending(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let mut byte = 0u8;
    // SAFETY: recv writes at most one byte to a live local. Only custody drains
    // this namespace-bound socket; the parent's duplicate is readiness-only.
    let result = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}

fn monitor_quiet(fd: BorrowedFd<'_>) -> io::Result<()> {
    if monitor_pending(fd)? {
        return Err(invalid("Host custody dependency notification pending"));
    }
    Ok(())
}

fn check_tcx(ifindex: u32, expected: &[TcxBinding]) -> io::Result<()> {
    for attach_type in [46, 47] {
        let mut programs = [0u32; 64];
        let mut links = [0u32; 64];
        // SAFETY: zero is the BPF query ABI default; both arrays stay live for syscall.
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.query.__bindgen_anon_1.target_ifindex = ifindex;
        attr.query.attach_type = attach_type;
        attr.query.__bindgen_anon_2.prog_cnt = programs.len() as u32;
        attr.query.prog_ids = programs.as_mut_ptr() as u64;
        attr.query.link_ids = links.as_mut_ptr() as u64;
        unsafe { bpf_syscall(bpf_cmd::BPF_PROG_QUERY as _, &mut attr) }
            .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        let count = unsafe { attr.query.__bindgen_anon_2.prog_cnt } as usize;
        let wanted = expected
            .iter()
            .find(|entry| entry.0 == ifindex && entry.1 == attach_type);
        match wanted {
            Some(entry) if count == 1 && programs[0] == entry.2 && links[0] == entry.3 => {}
            None if count == 0 => {}
            _ => {
                return Err(invalid(
                    "foreign/missing TCX or legacy linkless attachment in Host namespace",
                ));
            }
        }
    }
    Ok(())
}

fn link_fd(id: u32) -> io::Result<OwnedFd> {
    // SAFETY: zero initializes the BPF lookup ABI, and the returned FD is new.
    let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
    attr.__bindgen_anon_6.__bindgen_anon_1.link_id = id;
    let raw = unsafe { bpf_syscall(bpf_cmd::BPF_LINK_GET_FD_BY_ID as _, &mut attr) }
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    Ok(unsafe { OwnedFd::from_raw_fd(raw as _) })
}

fn check_link(fd: BorrowedFd<'_>, expected: TcxBinding) -> io::Result<()> {
    // SAFETY: the kernel fills an initialized generated ABI struct during syscall.
    let mut info: bpf_link_info = unsafe { std::mem::zeroed() };
    let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info_len = size_of::<bpf_link_info>() as u32;
    attr.info.info = (&mut info as *mut bpf_link_info) as u64;
    unsafe { bpf_syscall(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as _, &mut attr) }
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let tcx = unsafe { info.__bindgen_anon_1.tcx };
    if info.type_ != 11
        || info.id != expected.3
        || info.prog_id != expected.2
        || tcx.ifindex != expected.0
        || tcx.attach_type != expected.1
    {
        return Err(invalid("Host held TCX link identity changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apparmor_hook_record_boundary() {
        let body = |family: u8, fields: &[(u16, &[u8])]| {
            let mut bytes = vec![family, 0, 0, 0];
            for &(kind, value) in fields {
                put_attribute(&mut bytes, kind, value);
            }
            bytes
        };
        let fields: [(u16, &[u8]); 3] = [
            (4, b"apparmor_ip_postroute\0"),
            (1, &[0, 0, 0, 4]),
            (2, &[255, 255, 255, 31]),
        ];
        let mut inventory = Inventory::new();
        for family in [2, 10] {
            let good = body(family, &fields);
            inventory.record_hook(family, 4, true, &good).unwrap();
            assert_eq!(&inventory.records.last().unwrap()[2..], good);
            assert!(inventory.record_hook(family, 4, true, &good).is_err());
            assert!(
                Inventory::new()
                    .record_hook(family, 4, false, &good)
                    .is_err()
            );
            assert!(
                Inventory::new()
                    .record_hook(family, 3, true, &good)
                    .is_err()
            );
            assert!(Inventory::new().record_hook(7, 4, true, &good).is_err());
            for length in 0..good.len() {
                assert!(
                    Inventory::new()
                        .record_hook(family, 4, true, &good[..length])
                        .is_err()
                );
            }
            for offset in 0..4 {
                let mut bad = good.clone();
                bad[offset] ^= 1;
                assert!(Inventory::new().record_hook(family, 4, true, &bad).is_err());
            }
            let reversed = body(family, &[fields[2], fields[1], fields[0]]);
            assert!(
                Inventory::new()
                    .record_hook(family, 4, true, &reversed)
                    .is_ok()
            );
            for &(kind, value) in &fields {
                let mut duplicate = good.clone();
                put_attribute(&mut duplicate, kind, value);
                assert!(
                    Inventory::new()
                        .record_hook(family, 4, true, &duplicate)
                        .is_err()
                );
            }
            for extra in [0, 3, 5, 6, 7, 0x4001, 0x8004] {
                let mut foreign = good.clone();
                put_attribute(&mut foreign, extra, b"foreign\0");
                assert!(
                    Inventory::new()
                        .record_hook(family, 4, true, &foreign)
                        .is_err()
                );
            }
            for field in 0..3 {
                let mut bad_fields = fields;
                bad_fields[field].1 = b"wrong\0";
                assert!(
                    Inventory::new()
                        .record_hook(family, 4, true, &body(family, &bad_fields))
                        .is_err()
                );
                bad_fields = fields;
                bad_fields[field].0 |= 0x4000;
                assert!(
                    Inventory::new()
                        .record_hook(family, 4, true, &body(family, &bad_fields))
                        .is_err()
                );
            }
        }
        assert_eq!(inventory.netfilter_hooks, 2);
        assert_eq!(inventory.records.len(), 2);
        inventory.seal().unwrap();
        let mut changed = Inventory::new();
        changed.record_hook(2, 4, true, &body(2, &fields)).unwrap();
        changed.seal().unwrap();
        assert_ne!(inventory.records, changed.records);
    }

    #[test]
    fn plain_custody_rejects_hidden_transform_and_foreign_xdp() {
        let mut route = vec![0; 12];
        route[0] = 2;
        route[7] = 1;
        assert!(plain_route(&route, &[]).is_ok());
        put_attribute(&mut route, 21, &1u16.to_ne_bytes());
        assert!(plain_route(&route, &[]).is_err());
        let mut multipath = vec![0; 8];
        multipath[..2].copy_from_slice(&8u16.to_ne_bytes());
        multipath[4..8].copy_from_slice(&99u32.to_ne_bytes());
        let mut attributes = Vec::new();
        put_attribute(&mut attributes, 9, &multipath);
        assert!(route_attributes(&attributes, &[]).is_err());
        let mut xdp = Vec::new();
        put_attribute(&mut xdp, 2, &[0]);
        assert_eq!(plain_xdp(&xdp).unwrap(), 0);
        xdp.clear();
        put_attribute(&mut xdp, 2, &[2]);
        put_attribute(&mut xdp, 4, &1u32.to_ne_bytes());
        assert!(plain_xdp(&xdp).is_err());
        let mut body = vec![0; 16];
        body[2..4].copy_from_slice(&1u16.to_ne_bytes());
        body[4..8].copy_from_slice(&2u32.to_ne_bytes());
        put_attribute(&mut body, 1, &[2, 0, 0, 0, 0, 1]);
        put_attribute(&mut body, 3, b"eth0\0");
        put_attribute(&mut body, 4, &1500u32.to_ne_bytes());
        xdp.clear();
        put_attribute(&mut xdp, 2, &[0]);
        let without_xdp = body.clone();
        put_attribute(&mut body, 43, &xdp);
        let plain = parse_link(&body, [10, 0], &[]).unwrap();
        for program in [5u32, 7, 9] {
            let mut native = without_xdp.clone();
            xdp.clear();
            put_attribute(&mut xdp, 2, &[1]);
            put_attribute(&mut xdp, 4, &program.to_ne_bytes());
            put_attribute(&mut xdp, 5, &program.to_ne_bytes());
            put_attribute(&mut native, 43, &xdp);
            assert_eq!(
                parse_link(&native, [10, 0], &[(2, 5), (2, 7)]).is_ok(),
                program != 9
            );
            assert!(parse_link(&native, [10, 0], &[(3, program)]).is_err());
        }
        assert!(parse_link(&body, [10, 0], &[(2, 5), (2, 7)]).is_err());
        let mut loopback = body.clone();
        loopback[2..4].copy_from_slice(&772u16.to_ne_bytes());
        loopback[8..12].copy_from_slice(&(libc::IFF_LOOPBACK as u32).to_ne_bytes());
        assert!(parse_link(&loopback, [10, 0], &[]).is_ok());
        let mut private = body.clone();
        let mut info = Vec::new();
        put_attribute(&mut info, 1, b"veth\0");
        put_attribute(&mut private, 18, &info);
        put_attribute(&mut private, 5, &20u32.to_ne_bytes());
        put_attribute(&mut private, 37, &1u32.to_ne_bytes());
        assert!(parse_link(&private, [2, 0], &[]).is_ok());
        let mut mastered = body.clone();
        put_attribute(&mut mastered, 10, &99u32.to_ne_bytes());
        assert!(parse_link(&mastered, [10, 0], &[]).is_err());
        for kind in [
            b"vlan\0".as_slice(),
            b"bond\0",
            b"macsec\0",
            b"macvlan\0",
            b"veth\0",
        ] {
            let mut stacked = body.clone();
            let mut info = Vec::new();
            put_attribute(&mut info, 1, kind);
            put_attribute(&mut stacked, 18, &info);
            assert!(parse_link(&stacked, [10, 0], &[]).is_err());
        }
        let mut qdisc = vec![0; 20];
        qdisc[4..8].copy_from_slice(&2u32.to_ne_bytes());
        put_attribute(&mut qdisc, 1, b"noqueue\0");
        assert!(plain_qdisc(&qdisc, std::slice::from_ref(&plain)).is_ok());
        qdisc.truncate(20);
        put_attribute(&mut qdisc, 1, b"htb\0");
        assert!(plain_qdisc(&qdisc, &[plain]).is_err());
    }
}
