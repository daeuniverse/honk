use super::*;
use honk_ebpf_common::xdp_gateway::{
    CaptureRealmKey, EndpointHold, FragmentKey, FragmentVerdict, GATEWAY_REASON_COUNT, GatewayKey,
    LocalAddressKey,
};
use std::sync::Mutex;

pub type HoldValue = EndpointHold;

pub struct GatewayLoad<'a> {
    pub routing: &'a [aya_obj::generated::bpf_insn],
    pub maps: &'a GatewayMaps,
    pub conntrack: &'a ConntrackKfuncs,
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
}

impl GatewayLoad<'_> {
    pub(super) fn validate_and_retain(&self) -> io::Result<Vec<OwnedFd>> {
        if self.routing.is_empty() || self.routing.len() > 1_000_000 {
            return Err(invalid_data("invalid gateway routing instruction count"));
        }
        if self.conntrack.lookup == 0
            || self.conntrack.release == 0
            || ![0, 1].contains(&self.conntrack.lookup_offset)
            || ![0, 1].contains(&self.conntrack.release_offset)
            || (self.conntrack.btf.is_none()
                && (self.conntrack.lookup_offset != 0 || self.conntrack.release_offset != 0))
        {
            return Err(invalid_data("invalid gateway conntrack FD-array authority"));
        }
        let mut retained = Vec::new();
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
        if let Some(fd) = &self.conntrack.btf {
            retained.push(fd.try_clone()?);
        }
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
pub struct GatewayMaps {
    pub(super) realms: OwnedFd,
    pub(super) local_root: OwnedFd,
    pub(super) hold: OwnedFd,
    pub(super) fragments: OwnedFd,
    pub(super) stats: OwnedFd,
    pub(super) scratch: OwnedFd,
    pub(super) mode_flags: OwnedFd,
    cursor: Mutex<Option<GatewayKey>>,
    lookup_scratch: Mutex<Vec<u64>>,
    lookup_scratch_bytes: usize,
}

fn create<K, V>(kind: u32, entries: u32, name: &[u8], inner: RawFd) -> io::Result<OwnedFd> {
    bpf_fd(
        BPF_MAP_CREATE,
        &mut MapCreateAttr {
            map_type: kind,
            key_size: u32::try_from(size_of::<K>())
                .map_err(|_| invalid_data("gateway key too large"))?,
            value_size: u32::try_from(size_of::<V>())
                .map_err(|_| invalid_data("gateway value too large"))?,
            max_entries: entries,
            map_flags: 0,
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

fn lookup<K, V: Default>(fd: BorrowedFd<'_>, key: &K) -> io::Result<Option<V>> {
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

fn update<K, V>(fd: BorrowedFd<'_>, key: &K, value: &V, flags: u64) -> io::Result<()> {
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
        size_of::<Self>() + self.lookup_scratch_bytes
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
        let mut values = self
            .lookup_scratch
            .lock()
            .map_err(|_| invalid_data("gateway counter lock poisoned"))?;
        let key = honk_ebpf_common::xdp_gateway::GatewayReason::CtLookupError as u32;
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut elem(self.stats.as_fd(), &key, values.as_mut_ptr() as u64, 0),
        )?;
        values.iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or_else(|| invalid_data("gateway lookup error count overflow"))
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
        if realms.is_empty()
            || realms.len() > 4096
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
        let realms_fd = create::<CaptureRealmKey, u32>(1, 4096, b"honk_gw_realms", -1)?;
        for (key, realm) in realms {
            update(realms_fd.as_fd(), key, realm, 1)?;
        }
        bpf(22, &mut (realms_fd.as_raw_fd() as u32))?;
        let local = local_map(addresses)?;
        let local_root = create::<u32, u32>(12, 1, b"honk_gw_local_r", local.as_raw_fd())?;
        update(local_root.as_fd(), &0u32, &(local.as_raw_fd() as u32), 0)?;
        Ok(Self {
            realms: realms_fd,
            local_root,
            hold: create::<GatewayKey, EndpointHold>(1, 65536, b"honk_gw_hold", -1)?,
            fragments: create::<FragmentKey, FragmentVerdict>(9, 4096, b"honk_gw_frag", -1)?,
            stats: create::<u32, u64>(6, GATEWAY_REASON_COUNT, b"honk_gw_stats", -1)?,
            scratch: create::<u32, [u64; 64]>(6, 1, b"honk_gw_scratch", -1)?,
            mode_flags: create::<u32, u32>(2, 1, b"honk_gw_mode", -1)?,
            cursor: Mutex::new(None),
            lookup_scratch: Mutex::new(lookup_scratch),
            lookup_scratch_bytes,
        })
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

    pub fn lookup_hold(&self, key: &GatewayKey) -> io::Result<Option<EndpointHold>> {
        lookup(self.hold.as_fd(), key)
    }

    pub fn insert_hold(&self, key: &GatewayKey, now_ns: u64) -> io::Result<()> {
        let value = EndpointHold {
            first_seen_ns: now_ns,
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
            if !is_idle(before, now_ns, idle_ns) || retained(&next) {
                continue;
            }
            if self.lookup_hold(&next)? != Some(before) {
                continue;
            }
            match bpf(
                BPF_MAP_DELETE_ELEM,
                &mut elem(self.hold.as_fd(), &next, 0, 0),
            ) {
                Ok(_) => {
                    removed += 1;
                    *cursor = previous;
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(removed)
    }
}

fn is_idle(value: EndpointHold, now_ns: u64, idle_ns: u64) -> bool {
    now_ns
        .checked_sub(value.last_seen_ns)
        .is_some_and(|elapsed| elapsed > idle_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::xdp_gateway::HOLD_IDLE_NS;

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

    fn require_vm() {
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
                maps.retire_if_unretained(31_000_000_001, idle, |_| true)
                    .unwrap(),
                0
            );
            assert!(maps.lookup_hold(&key).unwrap().is_some());
        }
        assert_eq!(
            maps.retire_if_unretained(31_000_000_001, idle, |_| {
                update(
                    maps.hold.as_fd(),
                    &key,
                    &EndpointHold {
                        first_seen_ns: 1,
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
            maps.retire_if_unretained(62_000_000_002, idle, |_| false)
                .unwrap(),
            1
        );
        assert!(maps.lookup_hold(&key).unwrap().is_none());
        maps.insert_hold(&key, 1).unwrap();
        assert_eq!(
            maps.retire_if_unretained(31_000_000_001, idle, |_| {
                update(
                    maps.hold.as_fd(),
                    &key,
                    &EndpointHold {
                        first_seen_ns: 2,
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
        assert_eq!(maps.lookup_hold(&key).unwrap().unwrap().first_seen_ns, 2);
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
        maps.retire_if_unretained(31_000_000_001, idle, |key| {
            assert!(visited.insert(*key));
            true
        })
        .unwrap();
        assert_eq!(visited.len(), 64);
        maps.retire_if_unretained(31_000_000_001, idle, |key| {
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
                &EndpointHold {
                    first_seen_ns: 1,
                    last_seen_ns,
                },
                1,
            )
            .unwrap();
        }
        let mut queried = std::collections::HashSet::new();
        assert_eq!(
            maps.retire_if_unretained(now_ns, idle, |key| {
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
            maps.retire_if_unretained(now_ns + 1, idle, |_| false)
                .unwrap(),
            2
        );
        assert_eq!(maps.lookup_hold(&boundary).unwrap(), None);
        assert_eq!(maps.lookup_hold(&retained).unwrap(), None);
        assert!(maps.lookup_hold(&recent).unwrap().is_some());
    }

    #[test]
    fn retirement_uses_last_seen_and_strict_idle_horizon() {
        let old = EndpointHold {
            first_seen_ns: 1,
            last_seen_ns: 1,
        };
        assert!(!is_idle(old, 29_000_000_001, HOLD_IDLE_NS));
        assert!(!is_idle(old, 30_000_000_001, HOLD_IDLE_NS));
        assert!(is_idle(old, 31_000_000_001, HOLD_IDLE_NS));
        let hit = EndpointHold {
            last_seen_ns: 30_000_000_001,
            ..old
        };
        assert!(!is_idle(hit, 31_000_000_001, HOLD_IDLE_NS));
        assert!(!is_idle(hit, 1, HOLD_IDLE_NS));
    }
}
