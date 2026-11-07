//! Creates the daemon's TUN device and owns every kernel object its setup
//! adds. Each mutation is written ahead to a durable receipt under
//! `<data_dir>/state`, so a failed or killed run leaves exact evidence and its
//! containment in place instead of guessing what to delete. Nothing here
//! replays or adopts an old receipt.

use std::fs::File;
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, bail, ensure};
use honk_config::Config;
use honk_xsk::topology::{
    Topology, TunReadback, TunRoute, TunRouteKind, TunRule, TunRuleAction, TunRuleSelector,
    TunSpec, TunStage, tun_readback,
};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
use nix::sys::stat::{FileStat, Mode, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde_json::{Value, json};

use crate::netlink::{MutationError, NlSock};
use crate::state;

const SOURCE_SHA: &str = env!("HONK_SOURCE_SHA");
const RECEIPT_FORMAT: u32 = 1;

static INCARNATION: AtomicU64 = AtomicU64::new(0);

/// The only descriptor of the daemon's TUN device; the non-persistent link
/// exists exactly while it stays open. Never cloned or duplicated.
pub(super) struct TunDevice {
    fd: OwnedFd,
    ifindex: u32,
    incarnation: u64,
}

impl AsFd for TunDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// `attached`: `TUNSETIFF` had attached a device, which the dropped
/// descriptor then released.
struct OpenError {
    attached: bool,
    error: io::Error,
}

impl TunDevice {
    fn open(name: &str, incarnation: u64) -> Result<Self, OpenError> {
        let refused = |error: io::Error| OpenError {
            attached: false,
            error,
        };
        let mut request = interface_request(name).map_err(refused)?;
        let fd = open(
            "/dev/net/tun",
            OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| refused(errno.into()))?;
        // The ioctl takes a C short; IFF_TUN_EXCL is its sign bit.
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
        // SAFETY: TUNSETIFF reads and updates only this live, initialized ifreq.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(refused(io::Error::last_os_error()));
        }
        Self::attached(fd, name, incarnation).map_err(|error| OpenError {
            attached: true,
            error,
        })
    }

    fn attached(fd: OwnedFd, name: &str, incarnation: u64) -> io::Result<Self> {
        verify_attachment(&fd, name)?;
        let no_offloads: libc::c_ulong = 0;
        // SAFETY: TUNSETOFFLOAD takes its offload mask by value.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETOFFLOAD, no_offloads) } < 0 {
            return Err(io::Error::last_os_error());
        }
        same_namespace(&fd)?;
        let ifindex = nix::net::if_::if_nametoindex(name)?;
        Ok(Self {
            fd,
            ifindex,
            incarnation,
        })
    }
}

fn valid_attachment_flags(flags: libc::c_int) -> bool {
    flags & !libc::IFF_TUN_EXCL == libc::IFF_TUN | libc::IFF_NO_PI
}

fn verify_attachment(fd: &OwnedFd, name: &str) -> io::Result<()> {
    // SAFETY: zero initializes every byte returned by TUNGETIFF.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: the kernel writes only the initialized ifreq while fd stays owned.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: TUNGETIFF initializes this union member.
    let flags = libc::c_int::from(unsafe { request.ifr_ifru.ifru_flags } as u16);
    let actual = request
        .ifr_name
        .iter()
        .map(|&byte| byte as u8)
        .take_while(|&byte| byte != 0);
    if !actual.eq(name.bytes()) || !valid_attachment_flags(flags) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TUN attachment is not a single-queue IFF_TUN|IFF_NO_PI {name} (flags {flags:#x})"
            ),
        ));
    }
    Ok(())
}

fn interface_request(name: &str) -> io::Result<libc::ifreq> {
    // SAFETY: an all-zero ifreq is the empty C value.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.is_empty() || name.len() >= request.ifr_name.len() || name.bytes().any(|byte| byte == 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN name must be 1 to 15 bytes without NUL",
        ));
    }
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    Ok(request)
}

/// The receipt is named by this thread's namespace cookie, so the device must
/// live in the same namespace.
fn same_namespace(device: &OwnedFd) -> io::Result<()> {
    // SAFETY: TUNGETDEVNETNS takes no argument and returns a new descriptor or -1.
    let raw = unsafe { libc::ioctl(device.as_raw_fd(), libc::TUNGETDEVNETNS) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just installed this descriptor and nothing else owns it.
    let namespace = File::from(unsafe { OwnedFd::from_raw_fd(raw) }).metadata()?;
    let current = std::fs::metadata("/proc/thread-self/ns/net")?;
    if (namespace.dev(), namespace.ino()) != (current.dev(), current.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TUN device is outside the daemon's network namespace",
        ));
    }
    Ok(())
}

/// Strict reverse-path filtering drops replies the TUN injects whose source
/// routes elsewhere, and a per-device 0 cannot lower `all`.
fn admit_all_rp_filter(
    ipv4: bool,
    read: impl FnOnce() -> io::Result<String>,
) -> anyhow::Result<()> {
    if !ipv4 {
        return Ok(());
    }
    let value = read().context("read net.ipv4.conf.all.rp_filter")?;
    match value.trim() {
        "0" | "2" => Ok(()),
        "1" => bail!(
            "net.ipv4.conf.all.rp_filter is 1 (strict), which drops replies written to the TUN; set it to 0 or 2 before starting backend tun"
        ),
        other => bail!("unrecognized net.ipv4.conf.all.rp_filter value {other:?}"),
    }
}

/// Proves the bypass mark sticks on real TCP and UDP sockets and returns the
/// cookie of the namespace they were created in.
fn probe_marks(mark: u32) -> anyhow::Result<u64> {
    use socket2::{Domain, Protocol, Socket, Type};

    let mut cookie = 0;
    for (label, kind, protocol) in [
        ("TCP", Type::STREAM, Protocol::TCP),
        ("UDP", Type::DGRAM, Protocol::UDP),
    ] {
        let socket = Socket::new(Domain::IPV4, kind, Some(protocol))
            .with_context(|| format!("create {label} SO_MARK probe"))?;
        honk_outbound::util::set_mark_verified(&socket, mark).with_context(|| {
            format!("backend tun requires SO_MARK {mark:#x} on {label} sockets (CAP_NET_ADMIN)")
        })?;
        cookie = crate::netlink::fib::namespace_cookie(socket.as_raw_fd())
            .context("read SO_NETNS_COOKIE (Linux 5.14 or newer)")?;
    }
    Ok(cookie)
}

fn process_starttime() -> io::Result<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    // Field 22; the command name before it may contain spaces and parentheses.
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unparseable /proc/self/stat"))
}

struct Plan {
    name: String,
    mtu: u32,
    address4: Option<Ipv4Addr>,
    address6: Option<Ipv6Addr>,
    table: u32,
    rule_priority: u32,
    mark: u32,
    capture: Vec<(IpAddr, u8)>,
}

impl Plan {
    fn from_config(config: &Config) -> anyhow::Result<Self> {
        let tun = config
            .datapath
            .as_ref()
            .and_then(|datapath| datapath.tun.as_ref())
            .context("backend tun requires a datapath tun section")?;
        Ok(Self {
            name: tun.name.clone(),
            mtu: u32::from(tun.mtu),
            address4: tun.address4,
            address6: tun.address6,
            table: tun.table,
            rule_priority: tun.rule_priority,
            mark: config.global.effective_so_mark(),
            capture: tun
                .capture
                .iter()
                .map(|network| (network.addr(), network.prefix_len()))
                .collect(),
        })
    }

    fn spec(&self) -> TunSpec<'_> {
        TunSpec {
            name: &self.name,
            mtu: self.mtu,
            address4: self.address4,
            address6: self.address6,
            table: self.table,
            rule_priority: self.rule_priority,
            bypass_mark: self.mark,
            capture: &self.capture,
        }
    }

    fn capture_priority(&self) -> u32 {
        self.rule_priority + 4
    }

    fn addresses(&self) -> [Option<IpAddr>; 2] {
        [self.address4.map(IpAddr::V4), self.address6.map(IpAddr::V6)]
    }

    /// Without the IPv6 keys the kernel gives the link a random link-local
    /// address and accepts router advertisements on it.
    fn sysctls(&self) -> Vec<(String, &'static str)> {
        let name = &self.name;
        let mut sysctls = Vec::new();
        if Path::new(&format!("/proc/sys/net/ipv6/conf/{name}")).is_dir() {
            for (key, value) in [
                ("addr_gen_mode", "1"),
                ("accept_ra", "0"),
                ("autoconf", "0"),
            ] {
                sysctls.push((format!("net/ipv6/conf/{name}/{key}"), value));
            }
        }
        if self.address4.is_some() {
            sysctls.push((format!("net/ipv4/conf/{name}/rp_filter"), "0"));
        }
        sysctls
    }
}

fn write_sysctl(key: &str, value: &str) -> Result<(), MutationError> {
    let path = format!("/proc/sys/{key}");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(MutationError::Refused)?;
    file.write_all(value.as_bytes())
        .map_err(MutationError::Unconfirmed)?;
    match std::fs::read_to_string(&path) {
        Ok(actual) if actual.trim() == value => Ok(()),
        Ok(actual) => Err(MutationError::Unconfirmed(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{key} reads back {:?}", actual.trim()),
        ))),
        Err(error) => Err(MutationError::Unconfirmed(error)),
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Resource {
    Link,
    Sysctl { key: String, value: &'static str },
    Mtu(u32),
    Address(IpAddr),
    LinkUp,
    Route(TunRoute),
    Rule(TunRule),
}

impl Resource {
    /// Released by the kernel together with the link.
    fn link_scoped(&self) -> bool {
        !matches!(
            self,
            Self::Rule(_)
                | Self::Route(TunRoute {
                    kind: TunRouteKind::Blackhole,
                    ..
                })
        )
    }
}

/// `Intent` and `Removing` are written before the kernel call: the object may
/// or may not exist. `Refused` means nothing of this instance exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Intent,
    Acknowledged,
    Refused,
    Removing,
    Removed,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Acknowledged => "acknowledged",
            Self::Refused => "refused",
            Self::Removing => "removing",
            Self::Removed => "removed",
        }
    }
}

/// The receipt `tun-<netns_cookie>-<nonce>.json`. Every update writes a
/// private sibling, syncs it and renames it over the receipt only while the
/// receipt is still the inode this journal last wrote.
struct Journal {
    directory: File,
    location: PathBuf,
    file_name: String,
    // A saved dev/ino pair alone can be recycled after another writer unlinks it.
    file: File,
    pid: u32,
    starttime: u64,
    netns_cookie: u64,
    nonce: String,
    incarnation: u64,
    name: String,
    ifindex: Option<u32>,
    entries: Vec<(Resource, State)>,
}

fn create_private(directory: &File, name: &str) -> io::Result<File> {
    openat(
        directory,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn identity(stat: &FileStat) -> (libc::dev_t, libc::ino_t) {
    (stat.st_dev, stat.st_ino)
}

fn file_owned(directory: &File, name: &str, file: &File) -> io::Result<bool> {
    let named = fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    Ok(
        named.st_mode & libc::S_IFMT == libc::S_IFREG
            && identity(&named) == identity(&fstat(file)?),
    )
}

impl Journal {
    fn create(
        directory: File,
        location: PathBuf,
        netns_cookie: u64,
        nonce: u128,
        name: &str,
        incarnation: u64,
    ) -> io::Result<Self> {
        let nonce = format!("{nonce:032x}");
        let starttime = process_starttime()?;
        let file_name = format!("tun-{netns_cookie}-{nonce}.json");
        let file = create_private(&directory, &file_name)?;
        let journal = Self {
            directory,
            location,
            file_name,
            file,
            pid: std::process::id(),
            starttime,
            netns_cookie,
            nonce,
            incarnation,
            name: name.to_owned(),
            ifindex: None,
            entries: Vec::new(),
        };
        let written = journal
            .write_synced(&journal.file)
            .and_then(|()| journal.directory.sync_all());
        if let Err(error) = written {
            if journal.check_owned().is_ok() {
                let _ = unlinkat(
                    &journal.directory,
                    journal.file_name.as_str(),
                    UnlinkatFlags::NoRemoveDir,
                );
            }
            return Err(error);
        }
        Ok(journal)
    }

    fn path(&self) -> PathBuf {
        self.location.join(&self.file_name)
    }

    fn persist(&mut self) -> io::Result<()> {
        let temporary = format!("{}.tmp", self.file_name);
        let file = create_private(&self.directory, &temporary)?;
        let replaced = self
            .write_synced(&file)
            .and_then(|()| self.check_owned())
            .and_then(|()| {
                renameat(
                    &self.directory,
                    temporary.as_str(),
                    &self.directory,
                    self.file_name.as_str(),
                )
                .map_err(io::Error::from)
            });
        if let Err(error) = replaced {
            if file_owned(&self.directory, &temporary, &file).unwrap_or(false) {
                let _ = unlinkat(
                    &self.directory,
                    temporary.as_str(),
                    UnlinkatFlags::NoRemoveDir,
                );
            }
            return Err(error);
        }
        self.file = file;
        self.directory.sync_all()
    }

    fn check_owned(&self) -> io::Result<()> {
        if !file_owned(&self.directory, &self.file_name, &self.file)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "TUN setup receipt {} was replaced by another writer",
                    self.path().display()
                ),
            ));
        }
        Ok(())
    }

    fn remove(&self) -> io::Result<()> {
        self.check_owned()?;
        unlinkat(
            &self.directory,
            self.file_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        )?;
        self.directory.sync_all()
    }

    fn write_synced(&self, mut file: &File) -> io::Result<()> {
        file.write_all(&serde_json::to_vec_pretty(&self.json())?)?;
        file.sync_all()
    }

    fn ambiguous(&self) -> bool {
        self.entries
            .iter()
            .any(|(_, state)| matches!(state, State::Intent | State::Removing))
    }

    fn json(&self) -> Value {
        json!({
            "format": RECEIPT_FORMAT,
            "source_sha": SOURCE_SHA,
            "pid": self.pid,
            "starttime": self.starttime,
            "netns_cookie": self.netns_cookie,
            "nonce": self.nonce,
            "incarnation": self.incarnation,
            "name": self.name,
            "ifindex": self.ifindex,
            "ambiguous": self.ambiguous(),
            "resources": self
                .entries
                .iter()
                .map(|(resource, state)| self.entry(resource, *state))
                .collect::<Vec<_>>(),
        })
    }

    fn entry(&self, resource: &Resource, state: State) -> Value {
        let family = |ipv6: bool| if ipv6 { "inet6" } else { "inet" };
        let mut entry = match resource {
            Resource::Link => json!({"kind": "link", "name": self.name, "ifindex": self.ifindex,
                "flags": ["tun", "no_pi", "exclusive"], "offloads": 0, "persistent": false}),
            Resource::Sysctl { key, value } => {
                json!({"kind": "sysctl", "key": key, "value": value})
            }
            Resource::Mtu(mtu) => json!({"kind": "mtu", "ifindex": self.ifindex, "mtu": mtu}),
            Resource::Address(address) => {
                let prefix_len = if address.is_ipv4() { 32 } else { 128 };
                json!({
                    "kind": "address",
                    "ifindex": self.ifindex,
                    "address": format!("{address}/{prefix_len}"),
                    "flags": if address.is_ipv6() { vec!["nodad", "noprefixroute"] } else { vec!["noprefixroute"] },
                })
            }
            Resource::LinkUp => json!({"kind": "link_up", "ifindex": self.ifindex}),
            Resource::Route(route) => {
                let (kind, oif) = match route.kind {
                    TunRouteKind::Blackhole => ("blackhole", None),
                    TunRouteKind::Unicast { oif } => ("unicast", Some(oif)),
                };
                json!({
                    "kind": "route",
                    "family": family(route.destination.is_ipv6()),
                    "table": route.table,
                    "destination": format!("{}/{}", route.destination, route.prefix_len),
                    "type": kind,
                    "oif": oif,
                    "metric": route.metric,
                    "protocol": "static",
                    "scope": if oif.is_some() && route.destination.is_ipv4() { "link" } else { "universe" },
                })
            }
            Resource::Rule(rule) => {
                let (fwmark, fwmask, iif) = match rule.selector {
                    TunRuleSelector::Fwmark(mark) => (Some(mark), Some(u32::MAX), None),
                    TunRuleSelector::Iif => (None, None, Some(self.name.as_str())),
                    TunRuleSelector::All => (None, None, None),
                };
                let (action, table) = match rule.action {
                    TunRuleAction::Lookup(table) => ("lookup", Some(table)),
                    TunRuleAction::Prohibit => ("prohibit", None),
                };
                json!({
                    "kind": "rule",
                    "family": family(rule.ipv6),
                    "priority": rule.priority,
                    "fwmark": fwmark,
                    "fwmask": fwmask,
                    "iif": iif,
                    "action": action,
                    "table": table,
                })
            }
        };
        entry["state"] = json!(state.as_str());
        entry
    }

    fn describe(&self, index: usize) -> String {
        let (resource, state) = &self.entries[index];
        self.entry(resource, *state).to_string()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Slot {
    Empty,
    Exact,
    Foreign,
}

/// Whether the kernel slot of `resource` holds exactly it and nothing else.
fn slot(readback: &TunReadback, resource: &Resource) -> Slot {
    fn classify(mut matches: impl Iterator<Item = bool>) -> Slot {
        match matches.next() {
            None => Slot::Empty,
            Some(true) if matches.next().is_none() => Slot::Exact,
            _ => Slot::Foreign,
        }
    }
    match resource {
        Resource::Route(route) => classify(
            readback
                .routes
                .iter()
                .filter(|(table, destination, prefix_len, metric, _)| {
                    (*table, *destination, *prefix_len, *metric)
                        == (
                            route.table,
                            route.destination,
                            route.prefix_len,
                            route.metric,
                        )
                })
                .map(|(.., seen)| *seen == Some(*route)),
        ),
        Resource::Rule(rule) => classify(
            readback
                .rules
                .iter()
                .filter(|(ipv6, priority, _)| (*ipv6, *priority) == (rule.ipv6, rule.priority))
                .map(|(.., seen)| *seen == Some(*rule)),
        ),
        _ => Slot::Empty,
    }
}

/// Acknowledged containment in normal teardown order: capture rules, then
/// guard routes, then the bypass and return rules from the top priority down.
fn removal_order(entries: &[(Resource, State)], capture_priority: u32) -> Vec<usize> {
    let mut order: Vec<_> = entries
        .iter()
        .enumerate()
        .filter(|(_, (_, state))| *state == State::Acknowledged)
        .filter_map(|(index, (resource, _))| {
            let rank = match resource {
                Resource::Rule(rule) if rule.priority == capture_priority => (0, 0),
                Resource::Route(TunRoute {
                    kind: TunRouteKind::Blackhole,
                    ..
                }) => (1, 0),
                Resource::Rule(rule) => (2, u32::MAX - rule.priority),
                _ => return None,
            };
            Some((rank, index))
        })
        .collect();
    order.sort_unstable();
    order.into_iter().map(|(_, index)| index).collect()
}

/// Owner of the TUN link settings, addresses, guard routes and policy rules
/// this instance installed, and of their receipt.
pub(super) struct TunSetup {
    plan: Plan,
    journal: Journal,
    netlink: NlSock,
}

impl TunSetup {
    /// Creates the device and its containment: guards and all five rules per
    /// enabled family, without capture routes. The returned watcher was
    /// subscribed after the last own change, so any notice on it is foreign.
    pub(super) fn prepare(config: &Config) -> anyhow::Result<(Self, TunDevice, Topology)> {
        Self::prepare_in(config, honk_config::paths::data_dir())
    }

    fn prepare_in(config: &Config, data_dir: &Path) -> anyhow::Result<(Self, TunDevice, Topology)> {
        ensure!(
            !SOURCE_SHA.is_empty(),
            "backend tun records the full source commit in its setup receipt, but this binary has none; \
             build from a Git checkout or set HONK_SOURCE_SHA to the 40-character commit when building from a source archive"
        );
        let plan = Plan::from_config(config)?;
        admit_all_rp_filter(plan.address4.is_some(), || {
            std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")
        })?;
        let netns_cookie = probe_marks(plan.mark)?;
        let netlink = NlSock::new().context("open rtnetlink")?;
        let preflight = Topology::preflight_tun(&plan.spec()).context("TUN resource preflight")?;
        let directory = state::state_directory(data_dir, true, state::private)
            .context("open the private state directory for the TUN setup receipt")?;
        let incarnation = INCARNATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("TUN attachment incarnation exhausted"))?
            + 1;
        let journal = Journal::create(
            directory,
            data_dir.join(state::STATE_DIR),
            netns_cookie,
            rand::random(),
            &plan.name,
            incarnation,
        )
        .context("create the TUN setup receipt")?;
        let mut setup = Self {
            plan,
            journal,
            netlink,
        };
        match setup.install() {
            Ok((device, guarded)) => {
                drop(preflight);
                Ok((setup, device, guarded))
            }
            // The device was dropped inside `install`, so its link is gone.
            Err(error) => Err(setup.abandon(error)),
        }
    }

    fn install(&mut self) -> anyhow::Result<(TunDevice, Topology)> {
        let device = self.create_link()?;
        let ifindex = device.ifindex;
        for (key, value) in self.plan.sysctls() {
            let resource = Resource::Sysctl {
                key: key.clone(),
                value,
            };
            self.mutate(resource, |_| write_sysctl(&key, value))?;
        }
        let mtu = self.plan.mtu;
        self.mutate(Resource::Mtu(mtu), |netlink| {
            netlink.set_link_mtu(ifindex, mtu)
        })?;
        for address in self.plan.addresses().into_iter().flatten() {
            self.mutate(Resource::Address(address), |netlink| {
                netlink.add_tun_address(ifindex, address)
            })?;
        }
        self.mutate(Resource::LinkUp, |netlink| netlink.set_tun_link_up(ifindex))?;
        let guards = self.plan.spec().guard_routes();
        for route in guards {
            self.mutate(Resource::Route(route), |netlink| {
                netlink.add_tun_route(&route)
            })?;
        }
        let capture_priority = self.plan.capture_priority();
        let (capture, containment): (Vec<_>, Vec<_>) = self
            .plan
            .spec()
            .rules()
            .into_iter()
            .partition(|rule| rule.priority == capture_priority);
        let name = self.plan.name.clone();
        for rule in containment.into_iter().chain(capture) {
            self.mutate(Resource::Rule(rule), |netlink| {
                netlink.add_tun_rule(&rule, &name)
            })?;
        }
        let guarded = Topology::admit_tun(&self.plan.spec(), ifindex, TunStage::Guarded)
            .context("TUN guard admission")?;
        Ok((device, guarded))
    }

    fn create_link(&mut self) -> anyhow::Result<TunDevice> {
        let index = self.write_ahead(Resource::Link)?;
        match TunDevice::open(&self.plan.name, self.journal.incarnation) {
            Ok(device) => {
                self.journal.ifindex = Some(device.ifindex);
                self.settle(index, State::Acknowledged)?;
                Ok(device)
            }
            Err(OpenError { attached, error }) => {
                let state = if !attached {
                    State::Refused
                } else if nix::net::if_::if_nametoindex(self.plan.name.as_str())
                    == Err(Errno::ENODEV)
                {
                    State::Removed
                } else {
                    State::Intent
                };
                // A failed write here leaves the safer "intent" on disk.
                let _ = self.settle(index, state);
                Err(error).context("create the TUN device")
            }
        }
    }

    /// Installs the capture routes and returns the final watcher, subscribed
    /// and fully admitted with them in place.
    pub(super) fn activate(&mut self, device: &TunDevice) -> anyhow::Result<Topology> {
        self.check_device(device)?;
        let routes = self.plan.spec().capture_routes(device.ifindex);
        for route in routes {
            self.mutate(Resource::Route(route), |netlink| {
                netlink.add_tun_route(&route)
            })?;
        }
        Topology::admit_tun(&self.plan.spec(), device.ifindex, TunStage::Active)
            .context("TUN capture admission")
    }

    /// Removes the acknowledged capture routes so captured prefixes fall onto
    /// the guards. Rules and guards stay; unconfirmed routes leave with the link.
    pub(super) fn close_capture(&mut self, device: &TunDevice) -> anyhow::Result<()> {
        self.check_device(device)?;
        let active: Vec<usize> = (0..self.journal.entries.len())
            .filter(|&index| {
                matches!(
                    self.journal.entries[index],
                    (
                        Resource::Route(TunRoute {
                            kind: TunRouteKind::Unicast { .. },
                            ..
                        }),
                        State::Acknowledged
                    )
                )
            })
            .collect();
        if active.is_empty() {
            return Ok(());
        }
        let readback = self.readback()?;
        for &index in &active {
            ensure!(
                slot(&readback, &self.journal.entries[index].0) == Slot::Exact,
                "TUN capture route {} no longer holds exactly this instance's route; it leaves only with the descriptor",
                self.journal.describe(index)
            );
        }
        for index in active {
            if let Resource::Route(route) = self.journal.entries[index].0 {
                self.remove(index, |netlink| netlink.del_tun_route(&route))?;
            }
        }
        Ok(())
    }

    /// Call after the only device descriptor closed. A normal stop removes
    /// this instance's containment and receipt; otherwise both stay for the
    /// operator, as they do whenever ownership cannot be confirmed.
    pub(super) fn finish(mut self, normal: bool) -> anyhow::Result<()> {
        self.release_link()?;
        if normal {
            return self.remove_containment();
        }
        self.retain();
        Ok(())
    }

    /// Preparation failed with the device already closed: until a capture
    /// rule may exist, this instance's changes are removed; after it, the
    /// containment stays.
    fn abandon(mut self, error: anyhow::Error) -> anyhow::Error {
        let cleanup = self.release_link().and_then(|()| {
            if self.capture_admitted() {
                self.retain();
                Ok(())
            } else {
                self.remove_containment()
            }
        });
        match cleanup {
            Ok(()) => error,
            Err(cleanup) => error.context(format!("{cleanup:#}")),
        }
    }

    fn capture_admitted(&self) -> bool {
        let capture_priority = self.plan.capture_priority();
        self.journal.entries.iter().any(|(resource, state)| {
            *state != State::Refused
                && matches!(resource, Resource::Rule(rule) if rule.priority == capture_priority)
        })
    }

    fn check_device(&self, device: &TunDevice) -> anyhow::Result<()> {
        ensure!(
            Some(device.ifindex) == self.journal.ifindex
                && device.incarnation == self.journal.incarnation,
            "TUN device does not belong to this setup"
        );
        verify_attachment(&device.fd, &self.plan.name)
            .context("read back the owned TUN attachment")?;
        same_namespace(&device.fd)?;
        ensure!(
            nix::net::if_::if_nametoindex(self.plan.name.as_str())? == device.ifindex,
            "TUN name no longer identifies the owned interface"
        );
        for (key, value) in self.plan.sysctls() {
            ensure!(
                std::fs::read_to_string(format!("/proc/sys/{key}"))?.trim() == value,
                "owned TUN sysctl {key} changed"
            );
        }
        Ok(())
    }

    fn readback(&self) -> anyhow::Result<TunReadback> {
        // Index 0 never names a link: without one, only the tables are read.
        tun_readback(&self.plan.spec(), self.journal.ifindex.unwrap_or(0))
            .context("read back TUN kernel resources")
    }

    /// Confirms the kernel released the link with its descriptor, taking
    /// everything scoped to it.
    fn release_link(&mut self) -> anyhow::Result<()> {
        let Some(ifindex) = self.journal.ifindex else {
            return Ok(());
        };
        let readback = self.readback()?;
        let capture_left = readback.routes.iter().any(|(.., seen)| {
            matches!(seen, Some(TunRoute { kind: TunRouteKind::Unicast { oif }, .. }) if *oif == ifindex)
        });
        ensure!(
            !readback.link && readback.addresses.is_empty() && !capture_left,
            "TUN link {} (ifindex {ifindex}) outlived its descriptor; receipt {} retained",
            self.plan.name,
            self.journal.path().display()
        );
        for (resource, state) in &mut self.journal.entries {
            if resource.link_scoped() && *state != State::Refused {
                *state = State::Removed;
            }
        }
        self.journal
            .persist()
            .context("persist the TUN link release")
    }

    fn remove_containment(&mut self) -> anyhow::Result<()> {
        let receipt = self.journal.path();
        ensure!(
            !self.journal.ambiguous(),
            "unconfirmed TUN setup changes; containment and receipt {} retained for inspection",
            receipt.display()
        );
        let order = removal_order(&self.journal.entries, self.plan.capture_priority());
        if !order.is_empty() {
            let readback = self.readback()?;
            for &index in &order {
                ensure!(
                    slot(&readback, &self.journal.entries[index].0) == Slot::Exact,
                    "TUN {} no longer holds exactly this instance's object; containment and receipt {} retained",
                    self.journal.describe(index),
                    receipt.display()
                );
            }
            let name = self.plan.name.clone();
            for &index in &order {
                match self.journal.entries[index].0.clone() {
                    Resource::Route(route) => {
                        self.remove(index, |netlink| netlink.del_tun_route(&route))?
                    }
                    Resource::Rule(rule) => {
                        self.remove(index, |netlink| netlink.del_tun_rule(&rule, &name))?
                    }
                    _ => {}
                }
            }
            let readback = self.readback()?;
            for &index in &order {
                ensure!(
                    slot(&readback, &self.journal.entries[index].0) == Slot::Empty,
                    "TUN {} is still present after its removal; receipt {} retained",
                    self.journal.describe(index),
                    receipt.display()
                );
            }
        }
        self.journal
            .remove()
            .context("remove the TUN setup receipt")
    }

    fn retain(&self) {
        tracing::error!(
            receipt = %self.journal.path().display(),
            "TUN capture guards, policy rules and setup receipt retained; inspect and remove them before restarting"
        );
    }

    /// Persists `resource` as intended before the caller changes the kernel.
    fn write_ahead(&mut self, resource: Resource) -> anyhow::Result<usize> {
        self.journal.entries.push((resource, State::Intent));
        let index = self.journal.entries.len() - 1;
        if let Err(error) = self.journal.persist() {
            // Never attempted, whatever reached the disk.
            self.journal.entries[index].1 = State::Refused;
            return Err(error).context("persist the TUN setup intent");
        }
        Ok(index)
    }

    fn settle(&mut self, index: usize, state: State) -> anyhow::Result<()> {
        self.journal.entries[index].1 = state;
        self.journal
            .persist()
            .context("persist the TUN setup receipt")
    }

    fn mutate(
        &mut self,
        resource: Resource,
        apply: impl FnOnce(&mut NlSock) -> Result<(), MutationError>,
    ) -> anyhow::Result<()> {
        let index = self.write_ahead(resource)?;
        let (state, failure) = match apply(&mut self.netlink) {
            Ok(()) => (State::Acknowledged, None),
            Err(MutationError::Refused(error)) => (State::Refused, Some(error)),
            Err(MutationError::Unconfirmed(error)) => (State::Intent, Some(error)),
        };
        let settled = self.settle(index, state);
        match (failure, settled) {
            (Some(error), Ok(())) => {
                Err(error).with_context(|| format!("TUN setup {}", self.journal.describe(index)))
            }
            (Some(error), Err(journal)) => Err(error).with_context(|| {
                format!(
                    "TUN setup {}; receipt update also failed: {journal:#}",
                    self.journal.describe(index)
                )
            }),
            (None, settled) => settled,
        }
    }

    fn remove(
        &mut self,
        index: usize,
        apply: impl FnOnce(&mut NlSock) -> Result<(), MutationError>,
    ) -> anyhow::Result<()> {
        let previous = self.journal.entries[index].1;
        self.journal.entries[index].1 = State::Removing;
        if let Err(error) = self.journal.persist() {
            self.journal.entries[index].1 = previous;
            return Err(error).context("persist the TUN removal intent");
        }
        match apply(&mut self.netlink) {
            Ok(()) => self.settle(index, State::Removed),
            // The exact object was present just before; its fate is now unknown.
            Err(MutationError::Refused(error) | MutationError::Unconfirmed(error)) => {
                Err(error).with_context(|| format!("remove TUN {}", self.journal.describe(index)))
            }
        }
    }
}

#[cfg(test)]
mod tests;
