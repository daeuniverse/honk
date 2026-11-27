//! Socket-owned Host identity, independent of TUN HostFacts and ordinary TC.
use crate::ebpf::{
    PnameSupport,
    common::{btf, syscall},
};
use anyhow::{Context as _, ensure};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Map, MapData, SkStorage},
    programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, links::FdLink},
};
use aya_obj::generated::{
    BPF_F_NO_PREALLOC, bpf_attach_type::*, bpf_attr, bpf_cmd::BPF_PROG_QUERY,
    bpf_map_type::BPF_MAP_TYPE_SK_STORAGE,
};
use honk_ebpf_common::host::{HostSkDecision, HostSkIdentity};
use honk_netstack::{MemoryBudget, MemoryReservation};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
use std::{
    fs::File,
    io::{BufRead as _, BufReader, Read as _},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::MetadataExt as _,
    },
    path::{Path, PathBuf},
    sync::Arc,
};

const OBJECT: &[u8] = include_bytes!(env!("HONK_HOST_EBPF_OBJECT"));
const IDENTITY: &str = "HOST_SK_IDENTITY";
const DECISION: &str = "HOST_SK_DECISION";
const HOOKS: [(&str, aya_obj::generated::bpf_attach_type); 5] = [
    ("host_create", BPF_CGROUP_INET_SOCK_CREATE),
    ("host_connect4", BPF_CGROUP_INET4_CONNECT),
    ("host_connect6", BPF_CGROUP_INET6_CONNECT),
    ("host_sendmsg4", BPF_CGROUP_UDP4_SENDMSG),
    ("host_sendmsg6", BPF_CGROUP_UDP6_SENDMSG),
];

/// The links drop before the map descriptors, which drop before their charge.
pub(super) struct HostIdentity {
    _links: Vec<FdLink>,
    identity: MapData,
    decision: MapData,
    pid: Option<u32>,
    support: PnameSupport,
    _fixed: MemoryReservation,
    _hierarchy: Option<MemoryReservation>,
}

impl HostIdentity {
    pub(super) fn identity_fd(&self) -> BorrowedFd<'_> {
        self.identity.fd().as_fd()
    }
    pub(super) fn decision_fd(&self) -> BorrowedFd<'_> {
        self.decision.fd().as_fd()
    }
    pub(super) fn self_pid(&self) -> Option<u32> {
        self.pid
    }
    pub(super) fn pname_support(&self) -> PnameSupport {
        self.support
    }

    pub(super) fn load(budget: &Arc<MemoryBudget>, requires_pname: bool) -> anyhow::Result<Self> {
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        ensure!(page.is_power_of_two(), "invalid Host kernel page size");
        let cpus = aya::util::nr_cpus().map_err(|(_, e)| e)?.get() as usize;
        // Two local-storage bucket arrays, five copies of the linked code and JIT,
        // kernel BTF, file/link/map descriptors and their slab/page rounding. The
        // socket optmem elements have a separate kernel owner and lifetime.
        let fixed_bytes = 2 * cpus.next_power_of_two() * 128 + 128 * page + 96 * OBJECT.len();
        let fixed = budget
            .reserve(fixed_bytes)
            .context("Host identity fixed memory capacity")?;
        // Aya's verifier log can grow from 10 MiB to 16 MiB; keep the old buffer
        // and one retiring object charged across an argv0 -> comm retry.
        let _transient = budget
            .reserve((32 << 20) + fixed_bytes)
            .context("Host identity load memory capacity")?;
        let (root, hierarchy) = match cgroup_root().and_then(|root| {
            let memory = hierarchy_charge(&root, budget)?;
            Ok((root, memory))
        }) {
            Ok((root, memory)) => (Some(root), Some(memory)),
            Err(error) if requires_pname => {
                return Err(error.context("Host pname rules require cgroup2 root capture"));
            }
            Err(error) => {
                tracing::warn!(%error, "Host process capture unavailable");
                (None, None)
            }
        };
        let mut offsets = root.as_ref().and_then(|_| match argv_offsets(budget) {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::warn!(%error, "Host argv0 unavailable; trying thread names");
                None
            }
        });
        loop {
            let mut bytes = OBJECT.to_vec();
            specialize(&mut bytes, offsets)?;
            let mut object = EbpfLoader::new()
                .load(&bytes)
                .context("load Host socket-storage maps")?;
            ensure!(
                object.maps().count() == 2 && object.programs().count() == HOOKS.len(),
                "unexpected Host identity ELF layout"
            );
            let mut map_bytes = 0;
            for (name, width) in [
                (IDENTITY, size_of::<HostSkIdentity>()),
                (DECISION, size_of::<HostSkDecision>()),
            ] {
                syscall::validate_map_layout(
                    &object,
                    name,
                    BPF_MAP_TYPE_SK_STORAGE,
                    4,
                    width as u32,
                    0,
                    BPF_F_NO_PREALLOC,
                )?;
                let Map::SkStorage(data) =
                    object.map(name).context("Host socket storage missing")?
                else {
                    anyhow::bail!("invalid Host socket storage")
                };
                let fd = data.fd().as_fd();
                let info = syscall::raw_map_info(fd.as_raw_fd())?;
                ensure!(
                    info.btf_id != 0 && info.btf_key_type_id != 0 && info.btf_value_type_id != 0,
                    "Host storage missing kernel BTF types"
                );
                map_bytes += honk_xsk::kernel_memory_bytes(fd)?;
            }
            ensure!(
                map_bytes + 16 * page < fixed.bytes(),
                "Host empty socket maps exceed reservation"
            );
            let (links, pid, support, program_bytes) = if let Some(cgroup) = &root {
                match attach(&mut object, cgroup) {
                    Ok((links, pid, used)) => (
                        links,
                        Some(pid),
                        if offsets.is_some() {
                            PnameSupport::HostFull
                        } else {
                            PnameSupport::HostThreadName
                        },
                        used,
                    ),
                    Err(error) if offsets.take().is_some() => {
                        tracing::warn!(%error, "Host argv0 programs unavailable; trying thread names");
                        continue;
                    }
                    Err(error) if requires_pname => {
                        return Err(
                            error.context("Host pname rules require working socket identity")
                        );
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Host cgroup capture unavailable");
                        (Vec::new(), None, PnameSupport::Unavailable, 0)
                    }
                }
            } else {
                (Vec::new(), None, PnameSupport::Unavailable, 0)
            };
            ensure!(
                map_bytes + program_bytes + (16 + 4 * links.len()) * page + 4 * OBJECT.len()
                    <= fixed.bytes(),
                "Host identity kernel memory exceeds reservation"
            );
            tracing::debug!(
                empty_socket_map_bytes = map_bytes,
                program_bytes,
                fixed_bytes,
                "Host socket identity memory"
            );
            let mut take = |name| match object.take_map(name) {
                Some(Map::SkStorage(data)) => Ok(data),
                _ => anyhow::bail!("missing Host storage {name}"),
            };
            return Ok(Self {
                _links: links,
                identity: take(IDENTITY)?,
                decision: take(DECISION)?,
                pid,
                support,
                _fixed: fixed,
                _hierarchy: hierarchy,
            });
        }
    }
}

fn argv_offsets(budget: &Arc<MemoryBudget>) -> anyhow::Result<(i32, i32)> {
    let raw = btf::read_kernel_accounted_file(Path::new("/sys/kernel/btf/vmlinux"), budget)?;
    let btf = btf::Btf::parse(&raw.data).context("Host running BTF")?;
    let task_mm = btf::field(
        &btf,
        "task_struct",
        &["mm"],
        btf::Leaf::Pointer("mm_struct"),
    )?;
    let arg_start = btf::field(&btf, "mm_struct", &["arg_start"], btf::Leaf::Integer(8))?;
    Ok((task_mm.try_into()?, arg_start.try_into()?))
}

/// Replace only the pair of MOV64-immediate instructions emitted inside the
/// named BTF function. All relocations, .maps and BTF bytes stay intact.
fn specialize(bytes: &mut [u8], offsets: Option<(i32, i32)>) -> anyhow::Result<()> {
    let elf = object::File::parse(&*bytes)?;
    ensure!(
        elf.architecture() == object::Architecture::Bpf && elf.is_little_endian(),
        "Host identity ELF target"
    );
    let btf = elf
        .section_by_name(".BTF")
        .context("Host BTF section")?
        .data()?;
    ensure!(
        btf::Btf::parse(btf)
            .and_then(|b| b.find_type(12, "honk_host_name"))
            .is_some(),
        "Host identity BTF function missing"
    );
    let symbol = elf
        .symbol_by_name("honk_host_name")
        .context("Host capture symbol missing")?;
    ensure!(
        symbol.kind() == object::SymbolKind::Text && symbol.size() > 0,
        "Host capture symbol type"
    );
    let section = elf.section_by_index(symbol.section_index().context("Host capture section")?)?;
    ensure!(
        section.kind() == object::SectionKind::Text,
        "Host capture section type"
    );
    let (base, len) = section.file_range().context("Host capture file range")?;
    let start = symbol
        .address()
        .checked_sub(section.address())
        .context("Host capture address")?;
    let end = start
        .checked_add(symbol.size())
        .filter(|n| *n <= len)
        .context("Host capture size")?;
    let code = &section.data()?[usize::try_from(start)?..usize::try_from(end)?];
    ensure!(
        start % 8 == 0 && code.len() % 8 == 0,
        "unaligned Host capture symbol"
    );
    let markers = [0x484f4e31i32, 0x484f4e32];
    let mut at = [None; 2];
    for (i, insn) in code.as_chunks::<8>().0.iter().enumerate() {
        for (j, marker) in markers.iter().enumerate() {
            if insn[4..] != marker.to_le_bytes() {
                continue;
            }
            ensure!(
                insn[0] == 0xb7 && insn[1] < 10 && insn[2..4] == [0, 0] && at[j].is_none(),
                "invalid Host capture MOV64 specialization"
            );
            at[j] = Some(i * 8);
        }
    }
    let first = at[0].context("Host task offset instruction missing")?;
    ensure!(
        at[1] == Some(first + 8) && code[first + 1] != code[first + 9],
        "invalid Host offset instruction pair"
    );
    let patch = start + first as u64;
    ensure!(
        section
            .relocations()
            .all(|(off, _)| !(patch..patch + 16).contains(&off)),
        "relocated Host offset instructions"
    );
    let patch = usize::try_from(base + patch)?;
    let (task, arg) = offsets.unwrap_or((-1, 0));
    bytes[patch + 4..patch + 8].copy_from_slice(&task.to_le_bytes());
    bytes[patch + 12..patch + 16].copy_from_slice(&arg.to_le_bytes());
    Ok(())
}

fn cgroup_root() -> anyhow::Result<File> {
    // Aya chooses legacy PROG_ATTACH below 5.7 or if the version lookup fails.
    // Only the FD-owned branch is valid for this capture owner.
    use aya::util::KernelVersion;
    ensure!(
        KernelVersion::current().is_ok_and(|v| v >= KernelVersion::new(5, 7, 0)),
        "cgroup FD links unavailable"
    );
    let mut mountinfo = BufReader::new(File::open("/proc/thread-self/mountinfo")?);
    let mut line = String::new();
    // Mount options can make a procfs line larger than PATH_MAX. Reject an
    // oversized record before interpreting it as a complete mount description.
    const MOUNT_LINE_MAX: u64 = 64 * 1024;
    loop {
        line.clear();
        let n = (&mut mountinfo)
            .take(MOUNT_LINE_MAX + 1)
            .read_line(&mut line)?;
        if n == 0 {
            break;
        }
        ensure!(n as u64 <= MOUNT_LINE_MAX, "Host mountinfo record too long");
        let Some((mount, fs)) = line.split_once(" - ") else {
            continue;
        };
        if fs.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let mut fields = mount.split_whitespace().skip(3);
        if fields.next() != Some("/") {
            continue;
        }
        let Some(path) = fields.next() else { continue };
        // mountinfo octal-escapes these four bytes, including literal backslashes.
        let path = path
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        let root = File::open(path)?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if i128::from(unsafe { stat.assume_init() }.f_type) != i128::from(libc::CGROUP2_SUPER_MAGIC)
        {
            continue;
        }
        // cgroup.type exists on every non-root cgroup. A cgroup namespace can
        // display '/' for its own delegated subtree in mountinfo.
        let child_type = format!("/proc/thread-self/fd/{}/cgroup.type", root.as_raw_fd());
        match std::fs::metadata(child_type) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(root),
            Err(e) => return Err(e.into()),
            Ok(_) => continue,
        }
    }
    anyhow::bail!("Host requires the actual cgroup2 hierarchy root")
}

fn query(cgroup: &File, kind: u32, flags: u32, ids: &mut [u32]) -> anyhow::Result<usize> {
    let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
    attr.query.__bindgen_anon_1.target_fd = cgroup.as_raw_fd() as _;
    attr.query.attach_type = kind;
    attr.query.query_flags = flags;
    if !ids.is_empty() {
        attr.query.prog_ids = ids.as_mut_ptr() as u64;
        attr.query.__bindgen_anon_2.prog_cnt = u32::try_from(ids.len())?;
    }
    unsafe { syscall::bpf_syscall(BPF_PROG_QUERY as _, &mut attr) }
        .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))?;
    Ok(unsafe { attr.query.__bindgen_anon_2.prog_cnt } as usize)
}

// BPF_CGROUP_MAX_PROGS is 64 per attach type at a single cgroup. This
// query asks only for the root's own programs, not a descendant's effective set.
const LOCAL_PROGRAM_LIMIT: usize = 64;

fn attached<'a>(
    root: &File,
    kind: u32,
    ids: &'a mut [u32; LOCAL_PROGRAM_LIMIT],
) -> anyhow::Result<&'a [u32]> {
    let count = query(root, kind, 0, ids)?;
    ids.get(..count)
        .context("Host cgroup query exceeds local program limit")
}

// Linux recomputes inherited program arrays for each descendant on a root
// attach. Charge the observed hierarchy and its retiring arrays. Future cgroup
// creation/removal is initiated and allocated by the external hierarchy owner.
fn hierarchy_charge(root: &File, budget: &Arc<MemoryBudget>) -> anyhow::Result<MemoryReservation> {
    use aya_obj::generated::BPF_F_QUERY_EFFECTIVE;
    let path = PathBuf::from(format!("/proc/thread-self/fd/{}", root.as_raw_fd()));
    let mut stat = String::new();
    const STAT_MAX: usize = 16 * 1024;
    File::open(path.join("cgroup.stat"))?
        .take(STAT_MAX as u64 + 1)
        .read_to_string(&mut stat)?;
    ensure!(
        stat.len() <= STAT_MAX,
        "Host cgroup.stat exceeds loader bound"
    );
    let count = |key| {
        stat.lines()
            .find_map(|l| l.split_once(' ').filter(|(k, _)| *k == key))
            .context("missing cgroup.stat hierarchy count")?
            .1
            .parse::<usize>()
            .map_err(anyhow::Error::from)
    };
    let visible = count("nr_descendants")?
        .checked_add(1)
        .context("Host cgroup count overflow")?;
    let dying = count("nr_dying_descendants")?;
    // 64 bytes cover the array header and RCU record; 32 cover prog + both
    // storage pointers. Account a terminator and the newly added program, round
    // to a slab order, and hold four generations across attach/retry/detach.
    let charge = |count: usize| {
        count
            .checked_add(2)?
            .checked_mul(32)?
            .checked_add(64)?
            .checked_next_power_of_two()?
            .checked_mul(4)
    };
    let mut bytes = 0usize;
    visit_hierarchy(&path, root.metadata()?.dev(), visible, budget, |group| {
        for (_, kind) in HOOKS {
            let programs = query(group, kind as _, BPF_F_QUERY_EFFECTIVE, &mut [])?;
            bytes = charge(programs)
                .and_then(|v| bytes.checked_add(v))
                .context("Host cgroup charge overflow")?;
        }
        Ok(())
    })?;
    if dying != 0 {
        // Deleted directories cannot be queried. At most 64 local programs
        // per attach type at each level can enter an effective array.
        let max_chain = visible
            .checked_add(dying)
            .and_then(|n| n.checked_mul(LOCAL_PROGRAM_LIMIT))
            .context("Host dying cgroup depth overflow")?;
        let extra = charge(max_chain)
            .and_then(|v| v.checked_mul(HOOKS.len()))
            .and_then(|v| v.checked_mul(dying))
            .context("Host dying cgroup charge overflow")?;
        bytes = bytes
            .checked_add(extra)
            .context("Host cgroup charge overflow")?;
    }
    budget
        .reserve(bytes)
        .context("Host cgroup effective-array memory capacity")
}

fn visit_hierarchy(
    root: &Path,
    dev: u64,
    visible: usize,
    budget: &Arc<MemoryBudget>,
    mut visit: impl FnMut(&File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    // A single ReadDir is open at any time. glibc caps its getdents buffer at
    // 1 MiB; also cover the active directory's PATH_MAX and one d_name copy.
    ensure!(
        visible != 0 && root.as_os_str().len() < libc::PATH_MAX as usize,
        "invalid Host hierarchy root"
    );
    let slots = visible
        .checked_mul(size_of::<(PathBuf, MemoryReservation)>())
        .and_then(|n| n.checked_add(2 * size_of::<usize>()))
        .and_then(usize::checked_next_power_of_two)
        .and_then(|n| n.checked_add((1 << 20) + 4 * libc::PATH_MAX as usize))
        .context("Host cgroup traversal size overflow")?;
    let _scratch = budget
        .reserve(slots)
        .context("Host cgroup traversal scratch capacity")?;
    let mut pending = Vec::new();
    pending.try_reserve_exact(visible)?;
    let root_memory = budget
        .reserve((root.as_os_str().len() + 2 * size_of::<usize>()).next_power_of_two())
        .context("Host cgroup root path capacity")?;
    pending.push((root.to_owned(), root_memory));
    let mut seen = 0usize;
    while let Some(node) = pending.pop() {
        let path = &node.0;
        let group = File::open(path)?;
        ensure!(
            group.metadata()?.dev() == dev && seen < visible,
            "Host cgroup hierarchy changed while sizing inherited programs"
        );
        seen += 1;
        visit(&group)?;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            ensure!(
                pending.len() < visible - seen,
                "Host cgroup hierarchy grew during traversal"
            );
            let name = entry.file_name();
            let len = path.as_os_str().len() + 1 + name.len();
            ensure!(
                len < libc::PATH_MAX as usize,
                "Host cgroup path exceeds PATH_MAX"
            );
            // Round up for allocator size classes and a per-allocation header.
            let memory = budget
                .reserve((len + 2 * size_of::<usize>()).next_power_of_two())
                .context("Host cgroup pending path capacity")?;
            let mut child = PathBuf::new();
            child.try_reserve_exact(len)?;
            child.push(path);
            child.push(name);
            pending.push((child, memory));
        }
    }
    ensure!(
        seen == visible,
        "Host cgroup hierarchy is not fully visible for memory admission"
    );
    Ok(())
}

fn attach(object: &mut Ebpf, cgroup: &File) -> anyhow::Result<(Vec<FdLink>, u32, usize)> {
    let mut links = Vec::with_capacity(HOOKS.len());
    let mut program_bytes = 0usize;
    for (name, kind) in HOOKS {
        let mut before_ids = [0; LOCAL_PROGRAM_LIMIT];
        let before = attached(cgroup, kind as u32, &mut before_ids)?;
        let program = object
            .program_mut(name)
            .with_context(|| format!("missing Host hook {name}"))?;
        // Linux 6.12 cgroup_bpf_link_attach requires link_create.flags == 0
        // and internally attaches with ALLOW_MULTI. Aya Single supplies zero.
        let (link, info): (FdLink, _) = if kind == BPF_CGROUP_INET_SOCK_CREATE {
            let program: &mut CgroupSock = program.try_into()?;
            program.load()?;
            let id = program.attach(cgroup, CgroupAttachMode::Single)?;
            (program.take_link(id)?.try_into()?, program.info()?)
        } else {
            let program: &mut CgroupSockAddr = program.try_into()?;
            program.load()?;
            let id = program.attach(cgroup, CgroupAttachMode::Single)?;
            (program.take_link(id)?.try_into()?, program.info()?)
        };
        let mut after_ids = [0; LOCAL_PROGRAM_LIMIT];
        let after = attached(cgroup, kind as u32, &mut after_ids)?;
        ensure!(
            link.info()?.program_id() == info.id()
                && after.contains(&info.id())
                && before.iter().all(|id| after.contains(id)),
            "Host cgroup hook {name} coexistence readback"
        );
        program_bytes += info.memory_locked()? as usize
            + info.size_jitted() as usize
            + info
                .size_translated()
                .context("missing Host translated program size")? as usize;
        links.push(link);
    }
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let storage = SkStorage::<_, HostSkIdentity>::try_from(
        object.map(IDENTITY).context("Host socket identity map")?,
    )?;
    let value = storage
        .get(&socket, 0)
        .context("read Host identity for the owned canary socket")?;
    ensure!(
        value.pid != 0 && (1..=value.pname.len()).contains(&usize::from(value.pname_len)),
        "incomplete Host socket identity canary"
    );
    Ok((links, value.pid, program_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_and_deep_hierarchy_charges_pending_paths_before_allocation() {
        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        let dev = root.metadata().unwrap().dev();
        let width = 96usize;
        let depth = 48usize;
        for i in 0..width {
            std::fs::create_dir(root.join(format!("child-{i}"))).unwrap();
        }
        let mut branch = root.join("child-0");
        for _ in 0..depth {
            branch.push("next");
            std::fs::create_dir(&branch).unwrap();
        }
        let visible = 1 + width + depth;
        let budget = MemoryBudget::new(4 << 20);
        let mut at_root = 0;
        let mut visits = 0;
        visit_hierarchy(root, dev, visible, &budget, |_| {
            if visits == 0 {
                at_root = budget.used();
            }
            visits += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(visits, visible);
        assert_eq!(budget.used(), 0);

        let limited = MemoryBudget::new(at_root + 128);
        let mut visits = 0;
        let error = visit_hierarchy(root, dev, visible, &limited, |_| {
            visits += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(visits, 1);
        assert_eq!(error.to_string(), "Host cgroup pending path capacity");
        assert_eq!(limited.used(), 0);
        assert!(visit_hierarchy(root, dev, usize::MAX, &budget, |_| unreachable!()).is_err());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn embedded_identity_has_exact_socket_storage_and_specializes_both_modes() {
        assert!(OBJECT.len() < 32 * 1024);
        let obj = aya_obj::Object::parse(OBJECT).unwrap();
        assert!(obj.btf.is_some() && obj.btf_ext.is_some());
        assert_eq!(obj.maps.len(), 2);
        assert_eq!(obj.programs.len(), HOOKS.len());
        for (name, _) in HOOKS {
            assert!(obj.programs.contains_key(name));
        }
        for (name, width) in [
            (IDENTITY, size_of::<HostSkIdentity>()),
            (DECISION, size_of::<HostSkDecision>()),
        ] {
            let map = &obj.maps[name];
            assert_eq!(
                (map.map_type(), map.map_flags(), map.max_entries()),
                (BPF_MAP_TYPE_SK_STORAGE as _, BPF_F_NO_PREALLOC, 0)
            );
            assert_eq!((map.key_size(), map.value_size()), (4, width as u32));
            assert!(
                matches!(map, aya_obj::Map::Btf(m) if m.def.btf_key_type_id != 0 && m.def.btf_value_type_id != 0)
            );
        }
        let mut argv = OBJECT.to_vec();
        let mut comm = OBJECT.to_vec();
        specialize(&mut argv, Some((128, 456))).unwrap();
        specialize(&mut comm, None).unwrap();
        assert_ne!(argv, comm);
        assert!(specialize(&mut comm, None).is_err());
    }
}
