use super::tcx_aux::AuxDevicePair;
use super::*;
#[cfg(test)]
use honk_ebpf_common::xdp_gateway::HOLD_MANAGED;
use honk_ebpf_common::xdp_gateway::{
    CaptureRealmKey, FragmentKey, FragmentVerdict, GATEWAY_REALM_CAPACITY, GATEWAY_REASON_COUNT,
    GatewayDnsKey, GatewayDnsValue, GatewayHold, GatewayKey, GatewayReason, LocalAddressKey,
};
use honk_netstack::MemoryBudget;
use std::ptr::NonNull;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

mod arbitration;
pub use arbitration::{AuxReaderGrace, GatewayArbitration};

const GATEWAY_HOLD_ENTRIES: u32 = 65_536;
const GATEWAY_FRAGMENT_ENTRIES: u32 = 4096;
const BPF_MAP_LOOKUP_BATCH: u32 = 24;

pub type HoldValue = GatewayHold;

pub struct GatewayLoad<'a> {
    pub routing: &'a [aya_obj::generated::bpf_insn],
    pub maps: &'a GatewayMaps,
    pub conntrack: &'a ConntrackKfuncs,
    pub dns: Option<&'a GatewayDnsMaps>,
    pub arbitration: Option<&'a GatewayArbitration>,
}

#[repr(C)]
#[derive(Default)]
struct MapInfo {
    kind: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    entries: u32,
    flags: u32,
    name: [u8; 16],
}

impl GatewayLoad<'_> {
    pub(super) fn validate_and_retain(&self) -> io::Result<Vec<OwnedFd>> {
        let mut retained = self.validate_routing()?;
        if self.conntrack.lookup == 0
            || self.conntrack.release == 0
            || ![0, 1].contains(&self.conntrack.lookup_offset)
            || ![0, 1].contains(&self.conntrack.release_offset)
            || (self.conntrack.btf.is_none()
                && (self.conntrack.lookup_offset != 0 || self.conntrack.release_offset != 0))
        {
            return Err(invalid_data("invalid gateway conntrack FD-array authority"));
        }
        retained.reserve(10);
        for fd in [
            &self.maps.realms,
            &self.maps.local_root,
            &self.maps.hold,
            &self.maps.fragments,
            &self.maps.stats,
            &self.maps.scratch,
            &self.maps.mode_flags,
        ] {
            retained.push(fd.try_clone()?);
        }
        if let Some(arbitration) = self.arbitration {
            retained.push(arbitration.guards.try_clone()?);
            retained.push(arbitration.control.try_clone()?);
        }
        if let Some(fd) = &self.conntrack.btf {
            retained.push(fd.try_clone()?);
        }
        Ok(retained)
    }

    pub(super) fn validate_routing(&self) -> io::Result<Vec<OwnedFd>> {
        if self.routing.is_empty() || self.routing.len() > 1_000_000 {
            return Err(invalid_data("invalid gateway routing instruction count"));
        }
        let mut retained = Vec::new();
        let mut at = 0;
        let mut map_fds = Vec::new();
        while at < self.routing.len() {
            let insn = &self.routing[at];
            if insn.dst_reg() > 10 || insn.src_reg() > 10 {
                return Err(invalid_data("invalid gateway BPF register"));
            }
            if insn.code == LD_MAP {
                let Some(high) = self.routing.get(at + 1) else {
                    return Err(invalid_data("truncated gateway map instruction"));
                };
                if insn.src_reg() != 1
                    || high.code != 0
                    || high.imm != 0
                    || high.off != 0
                    || high.dst_reg() != 0
                    || high.src_reg() != 0
                    || insn.imm < 0
                {
                    return Err(invalid_data("invalid gateway map FD instruction"));
                }
                // SAFETY: the owner remains held by GatewayPolicy until loading completes.
                let fd = unsafe { BorrowedFd::borrow_raw(insn.imm) };
                let mut info = MapInfo::default();
                object_info(fd, &mut info)?;
                if info.kind != 11
                    || info.key_size != 20
                    || info.value_size != size_of::<honk_ebpf_common::DomainRouting>() as u32
                {
                    return Err(invalid_data("gateway routing fact map layout mismatch"));
                }
                if !map_fds.contains(&insn.imm) {
                    retained.push(fd.try_clone_to_owned()?);
                    map_fds.push(insn.imm);
                }
                at += 2;
                continue;
            }
            if matches!(insn.code & 7, 5 | 6) && ![CALL, EXIT].contains(&insn.code) {
                let target = i64::try_from(at)
                    .map_err(|_| invalid_data("gateway branch overflow"))?
                    .checked_add(1)
                    .and_then(|n| n.checked_add(i64::from(insn.off)))
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|n| *n < self.routing.len())
                    .ok_or_else(|| invalid_data("gateway branch target outside program"))?;
                if self.routing[target].code == 0 {
                    return Err(invalid_data("gateway branch targets map immediate"));
                }
            }
            if insn.code == CALL && (insn.src_reg() != 0 || insn.imm != 1) {
                return Err(invalid_data("unexpected gateway routing call"));
            }
            at += 1;
        }
        Ok(retained)
    }
}

#[derive(Debug)]
struct DnsLoadError {
    reason: &'static str,
    error: io::Error,
}

impl std::fmt::Display for DnsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.error)
    }
}

impl std::error::Error for DnsLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub(super) fn dns_load_error(reason: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), DnsLoadError { reason, error })
}

pub fn gateway_dns_load_failure(error: &io::Error) -> Option<&'static str> {
    Some(error.get_ref()?.downcast_ref::<DnsLoadError>()?.reason)
}

const DNS_FACTS: u32 = 4096;
const BPF_F_MMAPABLE: u32 = 1 << 10;

#[repr(C, align(64))]
struct EpochSlot {
    epoch: AtomicU64,
    _pad: [u8; 56],
}
const _: () = assert!(size_of::<EpochSlot>() == 64);

pub struct GatewayDnsMaps {
    pub(super) facts: OwnedFd,
    pub(super) epochs: OwnedFd,
    ids: [u32; 2],
    slots: NonNull<EpochSlot>,
    capacity: u32,
    cursor: Mutex<Option<GatewayDnsKey>>,
}

// SAFETY: the mapping stays alive with this owner, and only atomic stores access it.
unsafe impl Send for GatewayDnsMaps {}
unsafe impl Sync for GatewayDnsMaps {}

impl Drop for GatewayDnsMaps {
    fn drop(&mut self) {
        // SAFETY: sole owner of the original mmap address and length.
        unsafe {
            libc::munmap(
                self.slots.as_ptr().cast(),
                self.capacity as usize * size_of::<EpochSlot>(),
            )
        };
    }
}

impl GatewayDnsMaps {
    pub fn new(realm_capacity: u32) -> io::Result<Self> {
        if !(2..=GATEWAY_REALM_CAPACITY + 1).contains(&realm_capacity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid gateway DNS realm capacity",
            ));
        }
        if !cfg!(all(
            target_endian = "little",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported gateway DNS atomic architecture",
            ));
        }
        let facts = create::<GatewayDnsKey, GatewayDnsValue>(1, DNS_FACTS, b"dns_facts", -1)?;
        let epochs = create_with_flags::<u32, EpochSlot>(
            2,
            realm_capacity,
            b"dns_epochs",
            -1,
            BPF_F_MMAPABLE,
        )?;
        let mut ids = [0; 2];
        for (id, (fd, kind, key_size, value_size, entries, flags, name)) in ids.iter_mut().zip([
            (&facts, 1, 32, 40, DNS_FACTS, 0, &b"dns_facts"[..]),
            (
                &epochs,
                2,
                4,
                64,
                realm_capacity,
                BPF_F_MMAPABLE,
                &b"dns_epochs"[..],
            ),
        ]) {
            let mut info = MapInfo::default();
            object_info(fd.as_fd(), &mut info)?;
            if info.id == 0
                || info.kind != kind
                || info.key_size != key_size
                || info.value_size != value_size
                || info.entries != entries
                || info.flags != flags
                || info.name != object_name(name)
            {
                return Err(invalid_data("gateway DNS map layout mismatch"));
            }
            *id = info.id;
        }
        let slots = mmap_slots::<EpochSlot>(epochs.as_fd(), realm_capacity)?;
        Ok(Self {
            facts,
            epochs,
            ids,
            slots,
            capacity: realm_capacity,
            cursor: Mutex::new(None),
        })
    }

    pub(super) fn validate_program(&self, fd: BorrowedFd<'_>, id: u32) -> io::Result<()> {
        self.validate_typed_program(fd, id, BPF_PROG_TYPE_XDP)
    }

    pub(super) fn validate_typed_program(
        &self,
        fd: BorrowedFd<'_>,
        id: u32,
        kind: u32,
    ) -> io::Result<()> {
        // bpf_prog_info through map_ids. A prefix also works on the kernel floor.
        #[repr(C)]
        #[derive(Default)]
        struct Info {
            kind: u32,
            id: u32,
            tag: [u8; 8],
            jited_prog_len: u32,
            xlated_prog_len: u32,
            jited_prog_insns: u64,
            xlated_prog_insns: u64,
            load_time: u64,
            created_by_uid: u32,
            nr_map_ids: u32,
            map_ids: u64,
        }
        let identity_error = |err| dns_load_error("map_identity", err);
        let mut info = Info::default();
        object_info(fd, &mut info).map_err(identity_error)?;
        if info.id != id || info.kind != kind {
            return Err(identity_error(invalid_data(
                "gateway DNS program identity mismatch",
            )));
        }
        if info.jited_prog_len == 0 {
            return Err(dns_load_error(
                "jit_disabled",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "gateway DNS program has no JIT image",
                ),
            ));
        }
        let mut ids = Vec::<u32>::new();
        ids.try_reserve_exact(info.nr_map_ids as usize)
            .map_err(|_| {
                identity_error(io::Error::other("gateway DNS program map ID allocation"))
            })?;
        ids.resize(info.nr_map_ids as usize, 0);
        let mut info = Info {
            nr_map_ids: info.nr_map_ids,
            map_ids: ids.as_mut_ptr() as u64,
            ..Info::default()
        };
        object_info(fd, &mut info).map_err(identity_error)?;
        if info.nr_map_ids as usize != ids.len() || !self.ids.iter().all(|id| ids.contains(id)) {
            return Err(identity_error(invalid_data(
                "gateway program does not own both DNS map IDs",
            )));
        }
        Ok(())
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 2] {
        [self.facts.as_fd(), self.epochs.as_fd()]
    }

    pub fn memory_bytes(&self) -> usize {
        // The mapping aliases kernel array pages already charged by kernel_memory_bytes.
        size_of::<Self>()
    }

    pub fn set_epoch(&self, realm: u32, epoch: u64) {
        assert!(
            realm != 0 && realm < self.capacity,
            "invalid gateway DNS epoch index"
        );
        // SAFETY: this in-bounds cache-line aligned slot remains mapped for the borrow.
        unsafe { &(*self.slots.as_ptr().add(realm as usize)).epoch }.store(epoch, Ordering::SeqCst);
    }

    pub fn insert(&self, key: &GatewayDnsKey, value: &GatewayDnsValue) -> io::Result<()> {
        if key.realm_id == 0
            || key.realm_id >= self.capacity
            || key.reserved != 0
            || key.export_epoch == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid gateway DNS fact key",
            ));
        }
        update(self.facts.as_fd(), key, value, 1)
    }

    pub fn lookup(&self, key: &GatewayDnsKey) -> io::Result<Option<GatewayDnsValue>> {
        lookup(self.facts.as_fd(), key)
    }

    fn next_key(&self, key: Option<&GatewayDnsKey>) -> io::Result<Option<GatewayDnsKey>> {
        let mut next = GatewayDnsKey::default();
        let mut attr = MapElemAttr {
            map_fd: self.facts.as_raw_fd() as u32,
            reserved: 0,
            key: key.map_or(0, |key| std::ptr::from_ref(key) as u64),
            value: std::ptr::from_mut(&mut next) as u64,
            flags: 0,
        };
        match bpf(4, &mut attr) {
            Ok(_) => Ok(Some(next)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn reclaim(
        &self,
        should_remove: impl Fn(&GatewayDnsKey) -> bool,
    ) -> io::Result<(usize, usize, bool)> {
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|_| invalid_data("gateway DNS cursor poisoned"))?;
        if cursor.is_none() {
            *cursor = self.next_key(None)?;
        }
        let mut scanned = 0;
        let mut deleted = 0;
        while scanned < 256 {
            let Some(key) = *cursor else { break };
            // Fetch the successor before deleting: get_next_key restarts if its input vanished.
            let successor = self.next_key(Some(&key))?;
            scanned += 1;
            if should_remove(&key) {
                match bpf(
                    BPF_MAP_DELETE_ELEM,
                    &mut elem(self.facts.as_fd(), &key, 0, 0),
                ) {
                    Ok(_) => deleted += 1,
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => (),
                    Err(error) => return Err(error),
                }
            }
            *cursor = successor;
        }
        Ok((scanned, deleted, cursor.is_none()))
    }
}

fn mmap_slots<T>(fd: BorrowedFd<'_>, count: u32) -> io::Result<NonNull<T>> {
    let bytes = count as usize * size_of::<T>();
    // SAFETY: callers map the array's bounded value area, starting at its page-aligned first slot.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let Some(slots) = NonNull::new(ptr.cast::<T>()).filter(|p| p.as_ptr().is_aligned()) else {
        // SAFETY: mmap succeeded, but its address is unsuitable for Rust atomic access.
        unsafe { libc::munmap(ptr, bytes) };
        return Err(invalid_data("invalid gateway array mapping address"));
    };
    Ok(slots)
}

pub struct GatewayMaps {
    pub(super) realms: OwnedFd,
    pub(super) local_root: OwnedFd,
    pub(super) hold: OwnedFd,
    pub(super) fragments: OwnedFd,
    pub(super) stats: OwnedFd,
    pub(super) scratch: OwnedFd,
    pub(super) mode_flags: OwnedFd,
    auxiliary: Option<Box<AuxRegistry>>,
    cursor: Mutex<Option<GatewayKey>>,
    lookup_scratch: Mutex<Vec<u64>>,
    lookup_scratch_bytes: usize,
}

type RealmBinding = (u32, Option<Arc<AuxDevicePair>>);

struct AuxRegistry {
    physical: Box<[u32]>,
    // Retain the exact binding even if the kernel later reuses its ifindex.
    bindings: Mutex<Box<[RealmBinding]>>,
    bytes: usize,
}

fn create<K, V>(kind: u32, entries: u32, name: &[u8], inner: RawFd) -> io::Result<OwnedFd> {
    create_with_flags::<K, V>(kind, entries, name, inner, 0)
}

pub(super) fn create_with_flags<K, V>(
    kind: u32,
    entries: u32,
    name: &[u8],
    inner: RawFd,
    flags: u32,
) -> io::Result<OwnedFd> {
    bpf_fd(
        BPF_MAP_CREATE,
        &mut MapCreateAttr {
            map_type: kind,
            key_size: u32::try_from(size_of::<K>())
                .map_err(|_| invalid_data("gateway key too large"))?,
            value_size: u32::try_from(size_of::<V>())
                .map_err(|_| invalid_data("gateway value too large"))?,
            max_entries: entries,
            map_flags: flags,
            inner_map_fd: inner.max(0) as u32,
            numa_node: 0,
            map_name: object_name(name),
        },
    )
}

fn elem<K>(fd: BorrowedFd<'_>, key: &K, value: u64, flags: u64) -> MapElemAttr {
    MapElemAttr {
        map_fd: fd.as_raw_fd() as u32,
        reserved: 0,
        key: key as *const K as u64,
        value,
        flags,
    }
}

pub(super) fn lookup<K, V: Default>(fd: BorrowedFd<'_>, key: &K) -> io::Result<Option<V>> {
    let mut value = V::default();
    match bpf(
        BPF_MAP_LOOKUP_ELEM,
        &mut elem(fd, key, &mut value as *mut V as u64, 0),
    ) {
        Ok(_) => Ok(Some(value)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn update<K, V>(fd: BorrowedFd<'_>, key: &K, value: &V, flags: u64) -> io::Result<()> {
    bpf(
        BPF_MAP_UPDATE_ELEM,
        &mut elem(fd, key, value as *const V as u64, flags),
    )
    .map(|_| ())
}

fn local_map(addresses: &[LocalAddressKey]) -> io::Result<OwnedFd> {
    if addresses.len() > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many gateway local addresses",
        ));
    }
    let fd = create::<LocalAddressKey, u32>(1, 2048, b"honk_gw_local", -1)?;
    for address in addresses {
        update(fd.as_fd(), address, &1u32, 0)?;
    }
    bpf(22, &mut (fd.as_raw_fd() as u32))?;
    Ok(fd)
}

pub(super) fn possible_cpu_count(input: &str) -> io::Result<usize> {
    let mut count = 0usize;
    let mut previous = None;
    for range in input.trim().split(',') {
        let (first, last) = match range.split_once('-') {
            Some((first, last)) => (first, last),
            None => (range, range),
        };
        let first: usize = first
            .parse()
            .map_err(|_| invalid_data("invalid possible CPU range"))?;
        let last: usize = last
            .parse()
            .map_err(|_| invalid_data("invalid possible CPU range"))?;
        if last < first || previous.is_some_and(|previous| first <= previous) {
            return Err(invalid_data("overlapping possible CPU ranges"));
        }
        count = last
            .checked_sub(first)
            .and_then(|span| span.checked_add(1))
            .and_then(|span| count.checked_add(span))
            .ok_or_else(|| invalid_data("possible CPU count overflow"))?;
        previous = Some(last);
    }
    if count == 0 {
        return Err(invalid_data("empty possible CPU set"));
    }
    Ok(count)
}

impl GatewayMaps {
    pub fn memory_bytes(&self) -> usize {
        size_of::<Self>()
            + self.lookup_scratch_bytes
            + self.auxiliary.as_ref().map_or(0, |r| r.bytes)
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 7] {
        [
            &self.realms,
            &self.local_root,
            &self.hold,
            &self.fragments,
            &self.stats,
            &self.scratch,
            &self.mode_flags,
        ]
        .map(AsFd::as_fd)
    }

    pub fn stats_fd(&self) -> BorrowedFd<'_> {
        self.stats.as_fd()
    }
    pub fn lookup_errors(&self) -> io::Result<u64> {
        self.reason_count(GatewayReason::CtLookupError)
    }

    pub fn reason_count(&self, reason: GatewayReason) -> io::Result<u64> {
        let mut values = self
            .lookup_scratch
            .lock()
            .map_err(|_| invalid_data("gateway counter lock poisoned"))?;
        let key = reason as u32;
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut elem(self.stats.as_fd(), &key, values.as_mut_ptr() as u64, 0),
        )?;
        values.iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or_else(|| invalid_data("gateway reason count overflow"))
        })
    }

    pub fn local_map_fd(&self) -> io::Result<OwnedFd> {
        let id: u32 = lookup(self.local_root.as_fd(), &0u32)?
            .ok_or_else(|| invalid_data("gateway local-address root missing"))?;
        bpf_fd(14, &mut [id, 0u32, 0u32])
    }

    pub fn new(
        realms: &[(CaptureRealmKey, u32)],
        addresses: &[LocalAddressKey],
    ) -> io::Result<Self> {
        Self::new_with_aux(realms, addresses, &[])
    }

    pub fn new_with_aux(
        realms: &[(CaptureRealmKey, u32)],
        addresses: &[LocalAddressKey],
        aux_realms: &[u32],
    ) -> io::Result<Self> {
        if realms.is_empty()
            || realms.len().saturating_add(aux_realms.len()) > GATEWAY_REALM_CAPACITY as usize
            || aux_realms.len() > 8
            || aux_realms.iter().enumerate().any(|(i, id)| {
                *id == 0 || realms.iter().any(|(_, r)| r == id) || aux_realms[..i].contains(id)
            })
            || realms.iter().any(|(key, id)| {
                key.physical_ifindex == 0
                    || key.vlan_count > 2
                    || *id == 0
                    || key.vid.iter().any(|vid| *vid > 4095)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid gateway capture realms",
            ));
        }
        let cpus = possible_cpu_count(&std::fs::read_to_string(
            "/sys/devices/system/cpu/possible",
        )?)?;
        let mut lookup_scratch = Vec::new();
        lookup_scratch
            .try_reserve_exact(cpus)
            .map_err(|_| io::Error::other("gateway per-CPU scratch capacity"))?;
        lookup_scratch.resize(cpus, 0);
        let lookup_scratch_bytes = lookup_scratch.capacity() * size_of::<u64>();
        let auxiliary = if aux_realms.is_empty() {
            None
        } else {
            let physical: Box<[_]> = realms.iter().map(|(k, _)| k.physical_ifindex).collect();
            let bindings: Box<[_]> = aux_realms.iter().map(|&id| (id, None)).collect();
            let bytes = size_of::<AuxRegistry>()
                + std::mem::size_of_val(&*physical)
                + std::mem::size_of_val(&*bindings);
            Some(Box::new(AuxRegistry {
                physical,
                bindings: Mutex::new(bindings),
                bytes,
            }))
        };
        let realms_fd = create_with_flags::<CaptureRealmKey, u32>(
            1,
            GATEWAY_REALM_CAPACITY,
            b"honk_gw_realms",
            -1,
            if auxiliary.is_some() {
                aya_obj::generated::BPF_F_RDONLY_PROG
            } else {
                0
            },
        )?;
        for (key, realm) in realms {
            update(realms_fd.as_fd(), key, realm, 1)?;
        }
        if auxiliary.is_none() {
            bpf(22, &mut (realms_fd.as_raw_fd() as u32))?;
        }
        let local = local_map(addresses)?;
        let local_root = create::<u32, u32>(12, 1, b"honk_gw_local_r", local.as_raw_fd())?;
        update(local_root.as_fd(), &0u32, &(local.as_raw_fd() as u32), 0)?;
        Ok(Self {
            realms: realms_fd,
            auxiliary,
            local_root,
            hold: create::<GatewayKey, GatewayHold>(1, GATEWAY_HOLD_ENTRIES, b"honk_gw_hold", -1)?,
            fragments: create::<FragmentKey, FragmentVerdict>(
                9,
                GATEWAY_FRAGMENT_ENTRIES,
                b"honk_gw_frag",
                -1,
            )?,
            stats: create::<u32, u64>(6, GATEWAY_REASON_COUNT, b"honk_gw_stats", -1)?,
            scratch: create::<u32, [u64; 64]>(6, 1, b"honk_gw_scratch", -1)?,
            mode_flags: create::<u32, u32>(2, 1, b"honk_gw_mode", -1)?,
            cursor: Mutex::new(None),
            lookup_scratch: Mutex::new(lookup_scratch),
            lookup_scratch_bytes,
        })
    }

    fn aux_registry(&self) -> io::Result<&AuxRegistry> {
        self.auxiliary
            .as_deref()
            .ok_or_else(|| invalid_data("gateway has no auxiliary realms"))
    }

    pub fn bind_aux_realm(&self, pair: &Arc<AuxDevicePair>, realm: u32) -> io::Result<()> {
        pair.verify()?;
        let outer = pair.outer_ifindex();

        let registry = self.aux_registry()?;
        if registry.physical.contains(&outer) {
            return Err(invalid_data(
                "auxiliary ifindex belongs to physical capture",
            ));
        }
        let mut bindings = registry
            .bindings
            .lock()
            .map_err(|_| invalid_data("auxiliary registry poisoned"))?;
        let (_, bound) = bindings
            .iter_mut()
            .find(|(r, _)| *r == realm)
            .ok_or_else(|| invalid_data("unknown auxiliary realm"))?;
        if bound.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "auxiliary realm already bound",
            ));
        }
        let key = CaptureRealmKey {
            physical_ifindex: outer,
            ..Default::default()
        };
        update(self.realms.as_fd(), &key, &realm, 1)?;
        *bound = Some(Arc::clone(pair));
        Ok(())
    }

    pub fn unbind_aux_realm(&self, pair: &Arc<AuxDevicePair>, realm: u32) -> io::Result<()> {
        let outer = pair.outer_ifindex();
        let mut bindings = self
            .aux_registry()?
            .bindings
            .lock()
            .map_err(|_| invalid_data("auxiliary registry poisoned"))?;
        let (_, bound) = bindings
            .iter_mut()
            .find(|(r, owner)| {
                *r == realm && owner.as_ref().is_some_and(|owner| Arc::ptr_eq(owner, pair))
            })
            .ok_or_else(|| invalid_data("foreign auxiliary binding"))?;
        let key = CaptureRealmKey {
            physical_ifindex: outer,
            ..Default::default()
        };
        if lookup(self.realms.as_fd(), &key)? != Some(realm) {
            return Err(invalid_data("auxiliary capture key ownership changed"));
        }
        bpf(
            BPF_MAP_DELETE_ELEM,
            &mut elem(self.realms.as_fd(), &key, 0, 0),
        )?;
        *bound = None;
        Ok(())
    }

    /// Close both gates, unbind the capture key and synchronize kernel readers before retirement.
    pub fn clear_aux_realm(
        &self,
        realm: u32,
        arbitration: Option<&GatewayArbitration>,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<()> {
        let bindings = self
            .aux_registry()?
            .bindings
            .lock()
            .map_err(|_| invalid_data("auxiliary registry poisoned"))?;
        if !bindings
            .iter()
            .any(|(id, owner)| *id == realm && owner.is_none())
        {
            return Err(invalid_data("auxiliary realm is not offline"));
        }
        {
            // The periodic userspace sweep can also remove holds and refund native credits.
            let _collector = self
                .cursor
                .lock()
                .map_err(|_| invalid_data("gateway cursor poisoned"))?;
            scan_hash(
                self.hold.as_fd(),
                GATEWAY_HOLD_ENTRIES,
                budget,
                |key: &GatewayKey, hold: GatewayHold| {
                    if key.realm_id == realm {
                        self.delete_hold(key, hold, arbitration)?;
                    }
                    Ok(())
                },
            )?;
        }
        scan_hash(
            self.fragments.as_fd(),
            GATEWAY_FRAGMENT_ENTRIES,
            budget,
            |key: &FragmentKey, _: FragmentVerdict| {
                if key.realm_id == realm {
                    match bpf(
                        BPF_MAP_DELETE_ELEM,
                        &mut elem(self.fragments.as_fd(), key, 0, 0),
                    ) {
                        Err(e) if e.raw_os_error() != Some(libc::ENOENT) => return Err(e),
                        _ => (),
                    }
                }
                Ok(())
            },
        )
    }

    pub fn set_mode_flags(&self, flags: u32) -> io::Result<()> {
        update(self.mode_flags.as_fd(), &0u32, &flags, 0)
    }

    pub fn replace_local_addresses(&self, addresses: &[LocalAddressKey]) -> io::Result<()> {
        let local = local_map(addresses)?;
        update(
            self.local_root.as_fd(),
            &0u32,
            &(local.as_raw_fd() as u32),
            0,
        )
    }

    /// A lookup is an observation. Coordinated retirement confirms the stamp under the key's guard.
    pub fn lookup_hold(&self, key: &GatewayKey) -> io::Result<Option<GatewayHold>> {
        lookup(self.hold.as_fd(), key)
    }

    #[cfg(test)]
    pub(in crate::bpf) fn insert_hold(&self, key: &GatewayKey, now_ns: u64) -> io::Result<()> {
        if now_ns & HOLD_MANAGED != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Endpoint birth time",
            ));
        }
        let value = GatewayHold {
            stamp: now_ns,
            last_seen_ns: now_ns,
        };
        match update(self.hold.as_fd(), key, &value, 1) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn retire_if_unretained(
        &self,
        now_ns: u64,
        idle: Duration,
        arbitration: Option<&GatewayArbitration>,
        mut retained: impl FnMut(&GatewayKey) -> bool,
    ) -> io::Result<usize> {
        let idle_ns = u64::try_from(idle.as_nanos())
            .map_err(|_| invalid_data("gateway idle duration overflow"))?;
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|_| io::Error::other("gateway cursor poisoned"))?;
        let mut removed = 0;
        for _ in 0..64 {
            let previous = *cursor;
            let mut next = GatewayKey::default();
            let mut attr = MapElemAttr {
                map_fd: self.hold.as_raw_fd() as u32,
                reserved: 0,
                key: cursor
                    .as_ref()
                    .map_or(0, |key| key as *const GatewayKey as u64),
                value: &mut next as *mut GatewayKey as u64,
                flags: 0,
            };
            match bpf(4, &mut attr) {
                Ok(_) => *cursor = Some(next),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    *cursor = None;
                    break;
                }
                Err(error) => return Err(error),
            }
            let Some(before) = self.lookup_hold(&next)? else {
                continue;
            };
            if !is_idle(before, now_ns, idle_ns) || (!before.is_native_pending() && retained(&next))
            {
                continue;
            }
            if self.retire_observed(&next, before, now_ns, idle_ns, arbitration)? {
                removed += 1;
                *cursor = previous;
            }
        }
        Ok(removed)
    }

    fn retire_observed(
        &self,
        key: &GatewayKey,
        before: GatewayHold,
        now_ns: u64,
        idle_ns: u64,
        arbitration: Option<&GatewayArbitration>,
    ) -> io::Result<bool> {
        let retire = || {
            let Some(latest) = self.lookup_hold(key)? else {
                return Ok(false);
            };
            if latest != before || !is_idle(latest, now_ns, idle_ns) {
                return Ok(false);
            }
            self.delete_hold(key, latest, arbitration)
        };
        match arbitration {
            Some(arbitration) => arbitration.with_guard(key, retire),
            None => retire(),
        }
    }

    fn delete_hold(
        &self,
        key: &GatewayKey,
        hold: GatewayHold,
        arbitration: Option<&GatewayArbitration>,
    ) -> io::Result<bool> {
        let refund = if hold.is_native_pending() {
            Some(
                arbitration
                    .ok_or_else(|| invalid_data("native gateway hold without arbitration"))?,
            )
        } else {
            None
        };
        match bpf(BPF_MAP_DELETE_ELEM, &mut elem(self.hold.as_fd(), key, 0, 0)) {
            Ok(_) => {
                if let Some(arbitration) = refund {
                    arbitration.refund()?;
                }
                Ok(true)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[repr(C)]
struct LookupBatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

fn scan_hash<K: Copy + Default, V: Copy + Default>(
    fd: BorrowedFd<'_>,
    entries: u32,
    budget: &Arc<MemoryBudget>,
    mut visit: impl FnMut(&K, V) -> io::Result<()>,
) -> io::Result<()> {
    // HASH and LRU_HASH use a u32 bucket index that advances independently of row deletion.
    // These maps have power-of-two capacities, equal to their kernel bucket counts.
    let mut cursor = 0u32;
    let mut batch = 64.min(entries);
    loop {
        let len = batch as usize;
        let bytes = len
            .checked_mul(size_of::<K>() + size_of::<V>())
            .ok_or_else(|| invalid_data("gateway cleanup batch size overflow"))?;
        let _memory = budget.reserve(bytes).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "gateway cleanup batch capacity")
        })?;
        let mut keys = Vec::new();
        let mut values = Vec::new();
        keys.try_reserve_exact(len).map_err(io::Error::other)?;
        values.try_reserve_exact(len).map_err(io::Error::other)?;
        keys.resize(len, K::default());
        values.resize(len, V::default());

        loop {
            let mut next = 0u32;
            let mut attr = LookupBatchAttr {
                in_batch: if cursor == 0 {
                    0
                } else {
                    std::ptr::from_ref(&cursor) as u64
                },
                out_batch: &mut next as *mut u32 as u64,
                keys: keys.as_mut_ptr() as u64,
                values: values.as_mut_ptr() as u64,
                count: batch,
                map_fd: fd.as_raw_fd() as u32,
                elem_flags: 0,
                flags: 0,
            };
            let terminal = match bpf(BPF_MAP_LOOKUP_BATCH, &mut attr) {
                Ok(_) if attr.count != 0 && cursor < next && next < entries => false,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) && next == entries => true,
                Err(e) if e.raw_os_error() == Some(libc::ENOSPC) && batch < entries => {
                    if attr.count != 0 || next < cursor || next >= entries {
                        return Err(invalid_data(
                            "invalid gateway cleanup bucket capacity readback",
                        ));
                    }
                    // The kernel never splits a bucket. Retry it with larger charged buffers.
                    cursor = next;
                    batch = batch.saturating_mul(2).min(entries);
                    break;
                }
                Err(e) => return Err(e),
                Ok(_) => {
                    return Err(invalid_data(
                        "gateway cleanup bucket cursor did not advance",
                    ));
                }
            };
            if attr.count > batch {
                return Err(invalid_data("invalid gateway cleanup batch count"));
            }
            let count = attr.count as usize;
            for (key, value) in keys[..count].iter().zip(values[..count].iter().copied()) {
                visit(key, value)?;
            }
            if terminal {
                return Ok(());
            }
            cursor = next;
        }
    }
}

fn is_idle(value: GatewayHold, now_ns: u64, idle_ns: u64) -> bool {
    now_ns
        .checked_sub(value.last_seen_ns)
        .is_some_and(|elapsed| elapsed > idle_ns)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use honk_ebpf_common::xdp_gateway::HOLD_IDLE_NS;

    #[test]
    fn dns_capacity_rejects_out_of_range_before_map_creation() {
        for capacity in [0, 1, 4098, u32::MAX] {
            let error = GatewayDnsMaps::new(capacity)
                .err()
                .expect("invalid capacity admitted");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_gateway_dns_maps_pressure_epoch_stride_and_reclaim_lookahead() {
        require_vm();
        let dns = GatewayDnsMaps::new(3).unwrap();
        let epoch_slot =
            |realm: u32| -> [u64; 8] { lookup(dns.epochs.as_fd(), &realm).unwrap().unwrap() };
        assert_eq!(epoch_slot(0), [0; 8]);
        assert_eq!(epoch_slot(1), [0; 8]);
        dns.set_epoch(1, 7);
        dns.set_epoch(2, 3);
        assert_eq!(epoch_slot(1), [7, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(epoch_slot(2), [3, 0, 0, 0, 0, 0, 0, 0]);
        let key = |i: u32| GatewayDnsKey {
            realm_id: if i == 0 { 2 } else { 1 },
            export_epoch: if i == 0 { 3 } else { 7 },
            canonical_dst: std::net::Ipv4Addr::from(i).to_ipv6_mapped().octets(),
            reserved: 0,
        };
        let value = GatewayDnsValue {
            valid_before_mono_ns: u64::MAX,
            ..Default::default()
        };
        for i in 0..DNS_FACTS {
            dns.insert(&key(i), &value).unwrap();
        }
        assert_eq!(
            dns.insert(&key(0), &Default::default())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EEXIST)
        );
        assert_eq!(dns.lookup(&key(0)).unwrap(), Some(value));
        assert!(matches!(
            dns.insert(&key(DNS_FACTS), &value)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::E2BIG | libc::ENOSPC)
        ));
        dns.set_epoch(1, 8);
        let mut deleted = 0;
        for batch in 1..=DNS_FACTS / 256 {
            let (scanned, removed, end) = dns
                .reclaim(|k| k.realm_id == 1 && k.export_epoch < 8)
                .unwrap();
            assert_eq!(scanned, 256);
            assert_eq!(end, batch == DNS_FACTS / 256);
            deleted += removed;
        }
        assert_eq!(deleted, DNS_FACTS as usize - 1);
        assert_eq!(dns.lookup(&key(0)).unwrap(), Some(value));
        assert_eq!(dns.reclaim(|_| false).unwrap(), (1, 0, true));
        dns.insert(
            &GatewayDnsKey {
                export_epoch: 8,
                ..key(DNS_FACTS)
            },
            &value,
        )
        .unwrap();
    }

    #[test]
    fn possible_cpu_ranges_count_sparse_possible_cpus_and_reject_overlap() {
        assert_eq!(possible_cpu_count("0\n").unwrap(), 1);
        assert_eq!(possible_cpu_count("0-3,8,10-11\n").unwrap(), 7);
        for invalid in ["", "0-1,1-3", "3-2", "0,", "x", "0-18446744073709551615"] {
            assert!(possible_cpu_count(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_gateway_lookup_errors_sum_possible_cpu_values() {
        require_vm();
        let maps = maps();
        assert_eq!(maps.lookup_errors().unwrap(), 0);
        let mut values = maps.lookup_scratch.lock().unwrap();
        values[0] = 3;
        let last = values.len() - 1;
        values[last] += 5;
        let key = honk_ebpf_common::xdp_gateway::GatewayReason::CtLookupError as u32;
        bpf(
            BPF_MAP_UPDATE_ELEM,
            &mut elem(maps.stats.as_fd(), &key, values.as_ptr() as u64, 0),
        )
        .unwrap();
        drop(values);
        assert_eq!(maps.lookup_errors().unwrap(), 8);
    }

    pub(in crate::bpf) fn require_vm() {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(
            std::fs::read_to_string("/proc/cmdline")
                .unwrap()
                .contains("virtme.")
        );
        assert_ne!(
            std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
            std::fs::metadata("/proc/1/ns/net").unwrap().ino()
        );
        assert!(matches!(
            std::env::var("HONK_CI_VM_LANE").as_deref(),
            Ok("floor" | "recent")
        ));
        assert_eq!(
            std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap()
                .trim(),
            std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap()
        );
    }

    fn maps() -> GatewayMaps {
        GatewayMaps::new(
            &[(
                CaptureRealmKey {
                    physical_ifindex: 1,
                    ..Default::default()
                },
                1,
            )],
            &[],
        )
        .unwrap()
    }

    fn key(port: u16) -> GatewayKey {
        GatewayKey {
            realm_id: 1,
            family: 4,
            sport: port.to_be(),
            proto: 17,
            ..Default::default()
        }
    }

    pub(in crate::bpf) fn auxiliary_tun(requested: Option<u32>) -> (std::fs::File, u32) {
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .unwrap();
        if let Some(index) = requested {
            // SAFETY: TUNSETIFINDEX reads a native int from the supplied address.
            assert_eq!(
                unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFINDEX, &index) },
                0
            );
        }
        // SAFETY: the initialized ifreq carries a template and receives Linux's allocated name.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in req.ifr_name.iter_mut().zip(b"hcaux%d") {
            *dst = *src as libc::c_char;
        }
        req.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR | libc::IFF_TUN_EXCL) as _;
        assert_eq!(
            unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut req) },
            0
        );
        let index = unsafe { libc::if_nametoindex(req.ifr_name.as_ptr()) };
        assert_ne!(index, 0);
        assert_eq!(requested.unwrap_or(index), index);
        (fd, index)
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_aux_hash_batch_survives_deleted_successor() {
        require_vm();
        let fd = create::<FragmentKey, FragmentVerdict>(9, 256, b"honk_aux_churn", -1).unwrap();
        let value = FragmentVerdict::default();
        for id in 0..192 {
            update(
                fd.as_fd(),
                &FragmentKey {
                    id,
                    ..Default::default()
                },
                &value,
                0,
            )
            .unwrap();
        }
        let next = |key: Option<&FragmentKey>| {
            let mut next = FragmentKey::default();
            let mut attr = MapElemAttr {
                map_fd: fd.as_raw_fd() as u32,
                reserved: 0,
                key: key.map_or(0, |k| std::ptr::from_ref(k) as u64),
                value: std::ptr::from_mut(&mut next) as u64,
                flags: 0,
            };
            bpf(4, &mut attr).unwrap();
            next
        };
        let first = next(None);
        let evicted = next(Some(&first));
        let budget = MemoryBudget::new(1 << 20);
        let mut seen = [false; 192];
        scan_hash(
            fd.as_fd(),
            256,
            &budget,
            |key: &FragmentKey, _: FragmentVerdict| {
                let visited = &mut seen[key.id as usize];
                assert!(!*visited, "hash scan restarted at a previously visited key");
                *visited = true;
                if *key == first {
                    // Deleting GET_NEXT_KEY's saved successor would restart it at first.
                    bpf(BPF_MAP_DELETE_ELEM, &mut elem(fd.as_fd(), &evicted, 0, 0))?;
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(
            seen.iter()
                .enumerate()
                .all(|(id, seen)| *seen || id == evicted.id as usize)
        );
        assert!(
            lookup::<_, FragmentVerdict>(fd.as_fd(), &evicted)
                .unwrap()
                .is_none()
        );
        assert_eq!(budget.used(), 0);
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_aux_registry_and_retirement_preserve_other_realms() {
        use honk_ebpf_common::xdp_gateway::HOLD_NATIVE;

        require_vm();
        let (_outer, outer) = auxiliary_tun(None);
        let (_inner, inner) = auxiliary_tun(None);
        let budget = honk_netstack::MemoryBudget::new(128 << 20);
        let pair = Arc::new(AuxDevicePair::new(outer, inner, &budget).unwrap());
        let new_pair = Arc::new(AuxDevicePair::new(outer, inner, &budget).unwrap());
        let physical_pair = Arc::new(AuxDevicePair::new(1, inner, &budget).unwrap());
        let physical = CaptureRealmKey {
            physical_ifindex: 1,
            ..Default::default()
        };
        let maps = GatewayMaps::new_with_aux(&[(physical, 1)], &[], &[2, 3]).unwrap();
        let mut info = MapInfo::default();
        object_info(maps.realms.as_fd(), &mut info).unwrap();
        assert_ne!(info.flags & aya_obj::generated::BPF_F_RDONLY_PROG, 0);
        let ordinary = GatewayMaps::new(&[(physical, 1)], &[]).unwrap();
        assert_eq!(
            update(ordinary.realms.as_fd(), &physical, &2u32, 0)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        maps.bind_aux_realm(&pair, 2).unwrap();
        assert!(maps.bind_aux_realm(&physical_pair, 3).is_err());
        assert!(maps.bind_aux_realm(&pair, 3).is_err());
        assert!(maps.unbind_aux_realm(&new_pair, 2).is_err());
        assert!(maps.clear_aux_realm(2, None, &budget).is_err());
        assert_eq!(lookup(maps.realms.as_fd(), &physical).unwrap(), Some(1u32));
        let arb = GatewayArbitration::new(3).unwrap();
        update(arb.control.as_fd(), &0u32, &[2u64, 3, 0, 0, 0, 0, 0, 0], 0).unwrap();
        let native = GatewayHold {
            stamp: HOLD_MANAGED | HOLD_NATIVE | 1,
            last_seen_ns: 5,
        };
        for realm in [1, 2, 3] {
            let hold = GatewayKey {
                realm_id: realm,
                ..key(53)
            };
            if realm != 3 {
                update(maps.hold.as_fd(), &hold, &native, 1).unwrap();
            } else {
                maps.insert_hold(&hold, 5).unwrap();
            }
            let frag = FragmentKey {
                realm_id: realm,
                ..Default::default()
            };
            update(
                maps.fragments.as_fd(),
                &frag,
                &FragmentVerdict::default(),
                0,
            )
            .unwrap();
        }
        maps.unbind_aux_realm(&pair, 2).unwrap();
        let grace = AuxReaderGrace::new().unwrap();
        grace.synchronize().unwrap();
        for _ in 0..2 {
            maps.clear_aux_realm(2, Some(&arb), &budget).unwrap();
            assert_eq!((arb.pending(), arb.last_issued()), (1, 3));
            for realm in [1, 2, 3] {
                let hold = GatewayKey {
                    realm_id: realm,
                    ..key(53)
                };
                let frag = FragmentKey {
                    realm_id: realm,
                    ..Default::default()
                };
                assert_eq!(maps.lookup_hold(&hold).unwrap().is_some(), realm != 2);
                assert_eq!(
                    lookup::<_, FragmentVerdict>(maps.fragments.as_fd(), &frag)
                        .unwrap()
                        .is_some(),
                    realm != 2
                );
            }
        }
        maps.bind_aux_realm(&new_pair, 2).unwrap();
        assert!(maps.unbind_aux_realm(&pair, 2).is_err());
        maps.unbind_aux_realm(&new_pair, 2).unwrap();
        assert!(maps.clear_aux_realm(1, Some(&arb), &budget).is_err());
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_aux_tun_guard_requires_its_fd_and_outlives_return_link() {
        use crate::AuxTunGuard;
        use honk_netstack::MemoryBudget;

        require_vm();
        let (outer_fd, outer) = auxiliary_tun(None);
        let (inner_fd, inner) = auxiliary_tun(None);
        let budget = MemoryBudget::new(128 << 20);
        assert!(AuxTunGuard::install(outer, inner_fd.as_fd(), &budget).is_err());
        let guard = AuxTunGuard::install(inner, inner_fd.as_fd(), &budget).unwrap();
        let pair = Arc::new(AuxDevicePair::new(outer, inner, &budget).unwrap());
        assert!(update(pair.object_fds()[0], &0u32, &inner, 0).is_err());
        let ret = guard.attach_return(&pair).unwrap();
        ret.verify().unwrap();
        guard.verify().unwrap();
        pair.set_open(true).unwrap();
        pair.verify_open().unwrap();
        pair.set_open(false).unwrap();
        assert!(pair.verify_open().is_err());
        drop(ret);
        guard.verify().unwrap();
        // No durable guard may have been left behind by the rejected foreign-index operation.
        let outer_guard = AuxTunGuard::install(outer, outer_fd.as_fd(), &budget).unwrap();
        outer_guard.verify().unwrap();
        drop(inner_fd);
        assert!(pair.inner_gone().unwrap());
        assert_eq!(
            pair.verify().unwrap_err().raw_os_error(),
            Some(libc::ENODEV)
        );
        pair.set_open(false).unwrap();
        assert!(pair.set_open(true).is_err());
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_hold_sweep_retains_output_and_reread_changes() {
        require_vm();
        let maps = maps();
        let key = key(1234);
        maps.insert_hold(&key, 1).unwrap();
        let idle = Duration::from_secs(30);
        for _owner in ["queued", "exported", "cq"] {
            assert_eq!(
                maps.retire_if_unretained(31_000_000_001, idle, None, |_| true)
                    .unwrap(),
                0
            );
            assert!(maps.lookup_hold(&key).unwrap().is_some());
        }
        assert_eq!(
            maps.retire_if_unretained(31_000_000_001, idle, None, |_| {
                update(
                    maps.hold.as_fd(),
                    &key,
                    &GatewayHold {
                        stamp: 1,
                        last_seen_ns: 31_000_000_001,
                    },
                    2,
                )
                .unwrap();
                false
            })
            .unwrap(),
            0
        );
        assert!(maps.lookup_hold(&key).unwrap().is_some());
        assert_eq!(
            maps.retire_if_unretained(62_000_000_002, idle, None, |_| false)
                .unwrap(),
            1
        );
        assert!(maps.lookup_hold(&key).unwrap().is_none());
        maps.insert_hold(&key, 1).unwrap();
        assert_eq!(
            maps.retire_if_unretained(31_000_000_001, idle, None, |_| {
                update(
                    maps.hold.as_fd(),
                    &key,
                    &GatewayHold {
                        stamp: 2,
                        last_seen_ns: 1,
                    },
                    2,
                )
                .unwrap();
                false
            })
            .unwrap(),
            0
        );
        assert_eq!(maps.lookup_hold(&key).unwrap().unwrap().stamp, 2);
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_hold_sweep_native_reuse_guard_and_single_refund() {
        use honk_ebpf_common::xdp_gateway::{HOLD_NATIVE, HOLD_SEQUENCE_MAX};

        require_vm();
        let maps = maps();
        let key = GatewayKey {
            proto: 6,
            ..key(1234)
        };
        let arb = GatewayArbitration::new(3).unwrap();
        assert_eq!((arb.pending(), arb.last_issued()), (0, 3));
        update(arb.control.as_fd(), &0u32, &[1u64, 3, 0, 0, 0, 0, 0, 0], 0).unwrap();
        let native = GatewayHold {
            stamp: HOLD_MANAGED | HOLD_NATIVE | 1,
            last_seen_ns: 1,
        };
        let reused = GatewayHold {
            stamp: HOLD_MANAGED | HOLD_NATIVE | 2,
            ..native
        };
        update(maps.hold.as_fd(), &key, &native, 1).unwrap();
        let observed = maps.lookup_hold(&key).unwrap().unwrap();
        bpf(
            BPF_MAP_DELETE_ELEM,
            &mut elem(maps.hold.as_fd(), &key, 0, 0),
        )
        .unwrap();
        update(maps.hold.as_fd(), &key, &reused, 1).unwrap();
        let now = HOLD_IDLE_NS + 2;
        assert!(
            !maps
                .retire_observed(&key, observed, now, HOLD_IDLE_NS, Some(&arb))
                .unwrap()
        );
        assert_eq!(maps.lookup_hold(&key).unwrap(), Some(reused));
        assert_eq!(arb.pending(), 1);

        let sweep = |now| {
            maps.retire_if_unretained(now, Duration::from_nanos(HOLD_IDLE_NS), Some(&arb), |_| {
                panic!("native pending must ignore application retention")
            })
        };
        assert_eq!(sweep(now - 1).unwrap(), 0);
        update(arb.guards.as_fd(), &key, &7u32, 1).unwrap();
        assert_eq!(sweep(now).unwrap(), 0);
        assert_eq!(lookup(arb.guards.as_fd(), &key).unwrap(), Some(7u32));
        assert_eq!(arb.pending(), 1);
        bpf(
            BPF_MAP_DELETE_ELEM,
            &mut elem(arb.guards.as_fd(), &key, 0, 0),
        )
        .unwrap();
        assert_eq!(sweep(now).unwrap(), 1);
        assert_eq!(maps.lookup_hold(&key).unwrap(), None);
        assert_eq!(arb.pending(), 0);
        assert!(
            !maps
                .retire_observed(&key, reused, now, HOLD_IDLE_NS, Some(&arb))
                .unwrap()
        );
        assert_eq!(arb.pending(), 0);

        // An Endpoint at the same tuple keeps ordinary retention and never refunds native credit.
        let endpoint = GatewayHold {
            stamp: HOLD_MANAGED | 3,
            ..native
        };
        update(maps.hold.as_fd(), &key, &endpoint, 1).unwrap();
        let idle = Duration::from_nanos(HOLD_IDLE_NS);
        assert_eq!(
            maps.retire_if_unretained(now, idle, Some(&arb), |_| true)
                .unwrap(),
            0
        );
        assert_eq!(
            maps.retire_if_unretained(now, idle, Some(&arb), |_| false)
                .unwrap(),
            1
        );
        assert_eq!(arb.pending(), 0);
        update(
            arb.control.as_fd(),
            &0u32,
            &[0u64, HOLD_SEQUENCE_MAX + 1, 0, 0, 0, 0, 0, 0],
            0,
        )
        .unwrap();
        arb.synchronize_readers().unwrap();
        let highwater = arb.last_issued();
        assert_eq!(highwater, HOLD_SEQUENCE_MAX);
        drop(arb);
        let next = GatewayArbitration::new(highwater).unwrap();
        assert_eq!(next.last_issued(), HOLD_SEQUENCE_MAX);
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_hold_sweep_rechecks_activity_and_releases_guard_on_refund_error() {
        use honk_ebpf_common::xdp_gateway::HOLD_NATIVE;

        require_vm();
        let maps = maps();
        let arb = GatewayArbitration::new(1).unwrap();
        let key = GatewayKey {
            proto: 6,
            ..key(1234)
        };
        let observed = GatewayHold {
            stamp: HOLD_MANAGED | HOLD_NATIVE | 1,
            last_seen_ns: 1,
        };
        let now = HOLD_IDLE_NS + 2;
        let refreshed = GatewayHold {
            last_seen_ns: now,
            ..observed
        };
        update(maps.hold.as_fd(), &key, &refreshed, 1).unwrap();
        assert!(
            !maps
                .retire_observed(&key, observed, now, HOLD_IDLE_NS, Some(&arb))
                .unwrap()
        );
        assert_eq!(maps.lookup_hold(&key).unwrap(), Some(refreshed));
        // Both observations now qualify as idle, but this turn witnessed a refresh.
        let later = now + HOLD_IDLE_NS + 1;
        assert!(
            !maps
                .retire_observed(&key, observed, later, HOLD_IDLE_NS, Some(&arb))
                .unwrap()
        );
        assert_eq!(lookup::<_, u32>(arb.guards.as_fd(), &key).unwrap(), None);

        // The row outlives the idle horizon with a deliberately inconsistent zero credit.
        let error = maps
            .retire_if_unretained(
                later,
                Duration::from_nanos(HOLD_IDLE_NS),
                Some(&arb),
                |_| true,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(arb.pending(), 0);
        assert_eq!(maps.lookup_hold(&key).unwrap(), None);
        assert_eq!(lookup::<_, u32>(arb.guards.as_fd(), &key).unwrap(), None);
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_hold_sweep_full_guard_reports_error_without_evicting_other_keys() {
        require_vm();
        let maps = maps();
        let arb = GatewayArbitration::new(0).unwrap();
        let mut info = MapInfo::default();
        object_info(arb.guards.as_fd(), &mut info).unwrap();
        let possible = std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap();
        let cpus = possible_cpu_count(&possible).unwrap();
        assert_eq!(
            (info.kind, info.flags, info.entries as usize),
            (1, 0, cpus + 1)
        );
        let tuple = |id: u32| GatewayKey {
            realm_id: id,
            ..key(1234)
        };
        for id in 1..=info.entries {
            update(arb.guards.as_fd(), &tuple(id), &id, 1).unwrap();
        }
        let idle_key = tuple(info.entries + 1);
        maps.insert_hold(&idle_key, 1).unwrap();
        let error = maps
            .retire_if_unretained(
                HOLD_IDLE_NS + 2,
                Duration::from_nanos(HOLD_IDLE_NS),
                Some(&arb),
                |_| false,
            )
            .unwrap_err();
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::E2BIG | libc::ENOSPC)
        ));
        assert!(maps.lookup_hold(&idle_key).unwrap().is_some());
        for id in 1..=info.entries {
            assert_eq!(lookup(arb.guards.as_fd(), &tuple(id)).unwrap(), Some(id));
        }
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_hold_sweep_bounds_turn_and_preserves_cursor() {
        require_vm();
        let maps = maps();
        for port in 1..=75 {
            maps.insert_hold(&key(port), 1).unwrap();
        }
        let mut visited = std::collections::HashSet::new();
        let idle = Duration::from_secs(30);
        maps.retire_if_unretained(31_000_000_001, idle, None, |key| {
            assert!(visited.insert(*key));
            true
        })
        .unwrap();
        assert_eq!(visited.len(), 64);
        maps.retire_if_unretained(31_000_000_001, idle, None, |key| {
            assert!(visited.insert(*key));
            true
        })
        .unwrap();
        assert_eq!(visited.len(), 75);
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_gateway_g17_sweep_strict_idle_boundary_and_retention_callback() {
        require_vm();
        let maps = maps();
        let idle = Duration::from_nanos(HOLD_IDLE_NS);
        let now_ns = HOLD_IDLE_NS + 100;
        let boundary = key(1235);
        let recent = key(1236);
        let retained = key(1237);
        let unowned = key(1238);
        for (key, last_seen_ns) in [
            (boundary, 100),
            (recent, 101),
            (retained, 99),
            (unowned, 99),
        ] {
            update(
                maps.hold.as_fd(),
                &key,
                &GatewayHold {
                    stamp: 1,
                    last_seen_ns,
                },
                1,
            )
            .unwrap();
        }
        let mut queried = std::collections::HashSet::new();
        assert_eq!(
            maps.retire_if_unretained(now_ns, idle, None, |key| {
                queried.insert(*key);
                *key == retained
            })
            .unwrap(),
            1
        );
        assert_eq!(queried, [retained, unowned].into_iter().collect());
        assert!(maps.lookup_hold(&boundary).unwrap().is_some());
        assert!(maps.lookup_hold(&recent).unwrap().is_some());
        assert!(maps.lookup_hold(&retained).unwrap().is_some());
        assert_eq!(maps.lookup_hold(&unowned).unwrap(), None);
        assert_eq!(
            maps.retire_if_unretained(now_ns + 1, idle, None, |_| false)
                .unwrap(),
            2
        );
        assert_eq!(maps.lookup_hold(&boundary).unwrap(), None);
        assert_eq!(maps.lookup_hold(&retained).unwrap(), None);
        assert!(maps.lookup_hold(&recent).unwrap().is_some());
    }

    #[test]
    fn retirement_uses_last_seen_and_strict_idle_horizon() {
        let old = GatewayHold {
            stamp: 1,
            last_seen_ns: 1,
        };
        assert!(!is_idle(old, 29_000_000_001, HOLD_IDLE_NS));
        assert!(!is_idle(old, 30_000_000_001, HOLD_IDLE_NS));
        assert!(is_idle(old, 31_000_000_001, HOLD_IDLE_NS));
        let hit = GatewayHold {
            last_seen_ns: 30_000_000_001,
            ..old
        };
        assert!(!is_idle(hit, 31_000_000_001, HOLD_IDLE_NS));
        assert!(!is_idle(hit, 1, HOLD_IDLE_NS));
    }
}
