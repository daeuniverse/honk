//! Admit the running vmlinux/module BTF before emitting any TUN program.
use super::sys;
use crate::ebpf::common::btf::{self, Btf, Leaf, field};
use anyhow::{Context as _, ensure};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::{TunKernelOffsets, TunTraceTarget};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::Arc;

const BTF_LIMIT: usize = 256 << 20;

pub(super) fn zero_monotonic_namespace() -> anyhow::Result<()> {
    ensure!(
        crate::xdp::timens::monotonic_namespace_offset()? == Some(0),
        "Host requires zero current monotonic offset"
    );
    Ok(())
}

struct RawBtf {
    data: Vec<u8>,
    memory: MemoryReservation,
}

pub(super) struct KernelLayout {
    raw: RawBtf,
    btf: aya::Btf,
    parsed_memory: MemoryReservation,
    module: Option<(RawBtf, OwnedFd)>,
    // An open misc-device file pins tun's module until every actual attachment exists.
    _module_guard: File,
    pub offsets: TunKernelOffsets,
    pub read: TunTraceTarget,
    pub copy: TunTraceTarget,
    pub close: TunTraceTarget,
    pub socket_cookie: u32,
    pub task_mm: u32,
    pub mm_arg_start: u32,
}

impl KernelLayout {
    pub fn probe(budget: &Arc<MemoryBudget>) -> anyhow::Result<Self> {
        ensure!(
            cfg!(all(target_arch = "x86_64", target_endian = "little")),
            "TUN ordered ownership requires x86-64 little endian"
        );
        let module_guard = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")
            .context("TUN module lifetime hold")?;
        let raw = read_raw("/sys/kernel/btf/vmlinux", budget, 0)?;
        let base = Btf::parse(&raw.data).context("running vmlinux BTF")?;
        let parsed_bytes = base
            .aya_parse_allocation_bound()
            .context("TUN kernel BTF parse bound")?;
        let base_charge = raw
            .memory
            .bytes()
            .checked_add(parsed_bytes)
            .context("TUN BTF charge overflow")?;
        ensure!(
            base_charge <= BTF_LIMIT,
            "TUN kernel BTF exceeds 256 MiB construction bound"
        );
        let parsed_memory = budget
            .reserve(parsed_bytes)
            .context("TUN parsed BTF memory budget")?;
        let btf = aya::Btf::parse(&raw.data, Default::default())?;
        let module = if base.find_type(12, "tun_chr_read_iter").is_none() {
            let fd = module_btf_fd("tun")?;
            let data = read_raw("/sys/kernel/btf/tun", budget, base_charge)?;
            verify_module(fd.as_fd(), &data.data)?;
            Some((data, fd))
        } else {
            None
        };
        let merged = if let Some((module, _)) = &module {
            Some(merge(&raw, module, budget, base_charge)?)
        } else {
            None
        };
        let bytes = merged
            .as_ref()
            .map_or(raw.data.as_slice(), |value| value.data.as_slice());
        let actual = Btf::parse(bytes).context("TUN running composite BTF")?;
        for (name, ceiling) in [
            ("bpf_array", 65536),
            ("bpf_queue_stack", 65536),
            ("bpf_prog", 65536),
            ("bpf_prog_aux", 65536),
            ("bpf_link", 65536),
            ("bpf_tracing_link", 65536),
            ("bpf_cgroup_link", 65536),
            ("bpf_trampoline", 65536),
            ("bpf_prog_stats", 32),
        ] {
            let at = actual
                .find_type(4, name)
                .with_context(|| format!("TUN kernel allocation type {name}"))?;
            ensure!(
                actual
                    .u32_at(at + 8)
                    .is_some_and(|size| size != 0 && size <= ceiling),
                "TUN kernel allocation header exceeds admitted bound: {name}"
            );
        }
        let integer =
            |root, names: &[&str], width| field(&actual, root, names, Leaf::Integer(width));
        let pointer =
            |root, names: &[&str], target| field(&actual, root, names, Leaf::Pointer(target));
        let skb_cb = actual
            .sized_member_offset("sk_buff", "cb", 48)
            .context("TUN skb CB layout")?;
        let qdisc_data = actual
            .sized_member_offset("qdisc_skb_cb", "data", 20)
            .context("TUN actual BPF CB data region")?;
        let qdisc = actual
            .find_type(4, "qdisc_skb_cb")
            .context("TUN qdisc CB type")?;
        ensure!(
            actual.u32_at(qdisc + 8).is_some_and(|size| size <= 48) && qdisc_data <= 28,
            "TUN BPF CB exceeds skb CB"
        );
        let (sock_kernel_byte, sock_kernel_mask) = bitfield(&actual, "sock", "sk_kern_sock")?;
        let offsets = TunKernelOffsets {
            cast: function_id(&raw.data, &base, "bpf_cast_to_kern_ctx")?.0,
            skb_sk: pointer("sk_buff", &["sk"], "sock")?,
            skb_dev: pointer("sk_buff", &["dev"], "net_device")?,
            skb_users: integer("sk_buff", &["users", "refs", "counter"], 4)?,
            skb_len: integer("sk_buff", &["len"], 4)?,
            skb_truesize: integer("sk_buff", &["truesize"], 4)?,
            skb_iif: integer("sk_buff", &["skb_iif"], 4)?,
            skb_cb: skb_cb
                .checked_add(qdisc_data)
                .context("TUN CB offset overflow")?,
            skb_vlan_all: integer("sk_buff", &["vlan_all"], 4)?,
            skb_head: void_pointer(&actual, "sk_buff", "head", false)?,
            skb_end: integer("sk_buff", &["end"], 4)?,
            shinfo_gso_size: integer("skb_shared_info", &["gso_size"], 2)?,
            sock_state: integer("sock", &["__sk_common", "skc_state"], 1)?,
            sock_family: integer("sock", &["__sk_common", "skc_family"], 2)?,
            sock_type: integer("sock", &["sk_type"], 2)?,
            sock_protocol: integer("sock", &["sk_protocol"], 2)?,
            sock_mark: integer("sock", &["sk_mark"], 4)?,
            sock_cookie: integer("sock", &["__sk_common", "skc_cookie", "counter"], 8)?,
            sock_net: pointer("sock", &["__sk_common", "skc_net", "net"], "net")?,
            sock_kernel_byte,
            sock_kernel_mask,
            net_cookie: integer("net", &["net_cookie"], 8)?,
            dev_ifindex: integer("net_device", &["ifindex"], 4)?,
            dev_net: pointer("net_device", &["nd_net", "net"], "net")?,
            iocb_file: pointer("kiocb", &["ki_filp"], "file")?,
            iocb_complete: field(&actual, "kiocb", &["ki_complete"], Leaf::Function)?,
            file_private: void_pointer(&actual, "file", "private_data", true)?,
            file_flags: integer("file", &["f_flags"], 4)?,
            tfile_tun: pointer("tun_file", &["tun"], "tun_struct")?,
            tun_dev: pointer("tun_struct", &["dev"], "net_device")?,
            tun_flags: integer("tun_struct", &["flags"], 4)?,
            tun_numqueues: integer("tun_struct", &["numqueues"], 4)?,
            tun_numdisabled: integer("tun_struct", &["numdisabled"], 4)?,
            tun_vnet_size: integer("tun_struct", &["vnet_hdr_sz"], 4)?,
            tun_filter_prog: pointer("tun_struct", &["filter_prog"], "tun_prog")?,
            tun_prog_program: pointer("tun_prog", &["prog"], "bpf_prog")?,
            bpf_prog_aux: pointer("bpf_prog", &["aux"], "bpf_prog_aux")?,
            bpf_prog_aux_id: integer("bpf_prog_aux", &["id"], 4)?,
            filter_id: 0,
            iter_count: integer("iov_iter", &["count"], 8)?,
            iter_type: integer("iov_iter", &["iter_type"], 1)?,
            iter_ubuf: enum_value(&actual, "iter_type", "ITER_UBUF")?,
            iter_source: integer("iov_iter", &["data_source"], 1)?,
            iter_nofault: integer("iov_iter", &["nofault"], 1)?,
            task_leader: pointer("task_struct", &["group_leader"], "task_struct")?,
            task_start: integer("task_struct", &["start_boottime"], 8)?,
        };
        let base_types = type_count(&raw.data, &base)?;
        let target = |name, args: &[Argument], result| -> anyhow::Result<TunTraceTarget> {
            let (id, cursor) = function_id(bytes, &actual, name)?;
            prototype(&actual, cursor, args, result)?;
            let btf_fd = if id > base_types {
                module
                    .as_ref()
                    .context("TUN target has no actual module BTF FD")?
                    .1
                    .as_raw_fd()
            } else {
                0
            };
            Ok(TunTraceTarget {
                type_id: id,
                btf_fd,
            })
        };
        let read = target(
            "tun_chr_read_iter",
            &[Argument::Pointer("kiocb"), Argument::Pointer("iov_iter")],
            8,
        )?;
        let copy = target(
            "skb_copy_datagram_iter",
            &[
                Argument::Pointer("sk_buff"),
                Argument::Integer(4),
                Argument::Pointer("iov_iter"),
                Argument::Integer(4),
            ],
            4,
        )?;
        let close = target(
            "tun_chr_close",
            &[Argument::Pointer("inode"), Argument::Pointer("file")],
            4,
        )?;
        target(
            "tun_do_read",
            &[
                Argument::Pointer("tun_struct"),
                Argument::Pointer("tun_file"),
                Argument::Pointer("iov_iter"),
                Argument::Integer(4),
                Argument::VoidPointer,
            ],
            8,
        )?;
        let task_mm = pointer("task_struct", &["mm"], "mm_struct")?;
        let mm_arg_start = integer("mm_struct", &["arg_start"], 8)?;
        drop(merged);
        Ok(Self {
            socket_cookie: offsets.sock_cookie,
            offsets,
            read,
            copy,
            close,
            task_mm,
            mm_arg_start,
            raw,
            btf,
            parsed_memory,
            module,
            _module_guard: module_guard,
        })
    }

    pub fn btf(&self) -> &aya::Btf {
        &self.btf
    }
    pub fn memory_bytes(&self) -> usize {
        self.raw.memory.bytes()
            + self.parsed_memory.bytes()
            + self
                .module
                .as_ref()
                .map_or(0, |(raw, _)| raw.memory.bytes())
    }
}

fn read_raw(path: &str, budget: &Arc<MemoryBudget>, live: usize) -> anyhow::Result<RawBtf> {
    let mut file = File::open(path)?;
    let mut header = [0; 24];
    file.read_exact(&mut header)?;
    ensure!(
        u16::from_ne_bytes([header[0], header[1]]) == 0xeb9f,
        "TUN BTF endianness"
    );
    let extent = btf::declared_extent(&header).context("TUN BTF extent")?;
    let bytes = extent
        .checked_mul(2)
        .and_then(|x| x.checked_add(size_of::<Vec<u8>>()))
        .context("TUN raw BTF charge overflow")?;
    ensure!(
        live.checked_add(bytes).is_some_and(|x| x <= BTF_LIMIT),
        "TUN BTF exceeds 256 MiB construction bound"
    );
    let memory = budget.reserve(bytes).context("TUN raw BTF budget")?;
    let mut data = Vec::new();
    data.try_reserve_exact(extent)?;
    data.resize(extent, 0);
    data[..24].copy_from_slice(&header);
    file.read_exact(&mut data[24..])?;
    ensure!(
        file.read(&mut header[..1])? == 0,
        "TUN BTF undeclared trailing bytes"
    );
    Ok(RawBtf { data, memory })
}

fn sections(data: &[u8]) -> anyhow::Result<(&[u8], &[u8])> {
    let word = |off| u32::from_ne_bytes(data[off..off + 4].try_into().unwrap()) as usize;
    ensure!(data.len() >= 24, "short TUN BTF");
    let header = word(4);
    let section = |off: usize, len: usize| -> anyhow::Result<&[u8]> {
        let start = header.checked_add(off).context("TUN BTF offset overflow")?;
        let end = start.checked_add(len).context("TUN BTF section overflow")?;
        data.get(start..end).context("TUN BTF section extent")
    };
    Ok((section(word(8), word(12))?, section(word(16), word(20))?))
}
fn merge(
    base: &RawBtf,
    module: &RawBtf,
    budget: &Arc<MemoryBudget>,
    live: usize,
) -> anyhow::Result<RawBtf> {
    let (bt, bs) = sections(&base.data)?;
    let (mt, ms) = sections(&module.data)?;
    let types = bt
        .len()
        .checked_add(mt.len())
        .context("TUN split BTF type extent")?;
    let strings = bs
        .len()
        .checked_add(ms.len())
        .context("TUN split BTF string extent")?;
    let extent = 24usize
        .checked_add(types)
        .and_then(|x| x.checked_add(strings))
        .context("TUN split BTF extent")?;
    let charge = extent
        .checked_mul(2)
        .and_then(|x| x.checked_add(size_of::<Vec<u8>>()))
        .context("TUN split BTF charge")?;
    ensure!(
        live.checked_add(module.memory.bytes())
            .and_then(|x| x.checked_add(charge))
            .is_some_and(|x| x <= BTF_LIMIT),
        "TUN split BTF exceeds construction bound"
    );
    let memory = budget.reserve(charge).context("TUN split BTF budget")?;
    let mut data = Vec::new();
    data.try_reserve_exact(extent)?;
    data.extend_from_slice(&base.data[..24]);
    for (offset, value) in [
        (4, 24u32),
        (8, 0),
        (12, u32::try_from(types)?),
        (16, u32::try_from(types)?),
        (20, u32::try_from(strings)?),
    ] {
        data[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    data.extend_from_slice(bt);
    data.extend_from_slice(mt);
    data.extend_from_slice(bs);
    data.extend_from_slice(ms);
    Ok(RawBtf { data, memory })
}

fn type_count(data: &[u8], btf: &Btf<'_>) -> anyhow::Result<u32> {
    let (_, types) = walk_types(data, btf, None)?;
    Ok(types)
}
fn function_id(data: &[u8], btf: &Btf<'_>, name: &str) -> anyhow::Result<(u32, usize)> {
    walk_types(data, btf, Some(name))?
        .0
        .with_context(|| format!("actual TUN BTF function {name}"))
}
fn walk_types(
    data: &[u8],
    btf: &Btf<'_>,
    name: Option<&str>,
) -> anyhow::Result<(Option<(u32, usize)>, u32)> {
    let types = sections(data)?.0;
    let start = u32::from_ne_bytes(data[4..8].try_into()?) as usize
        + u32::from_ne_bytes(data[8..12].try_into()?) as usize;
    let end = start + types.len();
    let mut cursor = start;
    let mut id = 0u32;
    let mut found = None;
    while cursor < end {
        id = id.checked_add(1).context("TUN BTF type count overflow")?;
        let info = btf.u32_at(cursor + 4).context("TUN BTF type information")?;
        if info >> 24 & 31 == 12
            && name.is_some()
            && btf.string(btf.u32_at(cursor).context("TUN BTF function name")?) == name
        {
            ensure!(found.is_none(), "ambiguous TUN BTF function");
            found = Some((id, cursor));
        }
        cursor = cursor
            .checked_add(12)
            .and_then(|x| x.checked_add(btf::type_extra_len(info >> 24 & 31, info & 0xffff)?))
            .context("TUN BTF record extent")?;
        ensure!(cursor <= end, "TUN BTF type section overflow");
    }
    Ok((found, id))
}

#[derive(Clone, Copy)]
enum Argument {
    Pointer(&'static str),
    VoidPointer,
    Integer(u32),
}
fn prototype(btf: &Btf<'_>, function: usize, args: &[Argument], result: u32) -> anyhow::Result<()> {
    let proto = btf
        .resolve_modifiers(btf.u32_at(function + 8).context("TUN FUNC prototype")?)
        .context("TUN resolved prototype")?;
    ensure!(
        btf.kind(proto) == Some(13)
            && btf.u32_at(proto + 4).map(|x| x & 0xffff) == Some(args.len() as u32),
        "TUN function arity"
    );
    fn integer(btf: &Btf<'_>, id: u32, width: u32) -> anyhow::Result<()> {
        let at = btf.resolve_modifiers(id).context("TUN integer type")?;
        ensure!(
            btf.kind(at) == Some(1)
                && btf.type_size(id) == Some(width)
                && btf.u32_at(at + 12) == Some((1 << 24) | (width * 8)),
            "TUN signed integer prototype width"
        );
        Ok(())
    }
    integer(
        btf,
        btf.u32_at(proto + 8).context("TUN return type")?,
        result,
    )?;
    for (index, expected) in args.iter().enumerate() {
        let id = btf
            .u32_at(proto + 16 + index * 8)
            .context("TUN argument type")?;
        match expected {
            Argument::Integer(width) => integer(btf, id, *width)?,
            Argument::Pointer(target) => {
                let at = btf.resolve_modifiers(id).context("TUN argument pointer")?;
                ensure!(
                    btf.kind(at) == Some(2)
                        && btf.resolve_modifiers(btf.u32_at(at + 8).context("TUN pointee")?)
                            == btf.find_type(4, target),
                    "TUN argument pointer target"
                );
            }
            Argument::VoidPointer => {
                let at = btf.resolve_modifiers(id).context("TUN void pointer")?;
                ensure!(
                    btf.kind(at) == Some(2) && btf.u32_at(at + 8) == Some(0),
                    "TUN void pointer prototype"
                );
            }
        }
    }
    Ok(())
}

fn void_pointer(btf: &Btf<'_>, root: &str, name: &str, void: bool) -> anyhow::Result<u32> {
    let owner = btf.find_type(4, root).context("TUN pointer owner")?;
    let info = btf.u32_at(owner + 4).context("TUN pointer owner fields")?;
    let mut found = None;
    for index in 0..(info & 0xffff) as usize {
        let pos = owner + 12 + index * 12;
        if btf.string(btf.u32_at(pos).context("TUN pointer field name")?) != Some(name) {
            continue;
        }
        let bits = btf.u32_at(pos + 8).context("TUN pointer field offset")?;
        ensure!(
            info >> 31 == 0 || bits >> 24 == 0,
            "TUN pointer is a bitfield"
        );
        let bits = if info >> 31 == 0 {
            bits
        } else {
            bits & 0xffffff
        };
        ensure!(
            bits % 64 == 0 && found.is_none(),
            "ambiguous/unaligned TUN pointer"
        );
        let at = btf
            .resolve_modifiers(btf.u32_at(pos + 4).context("TUN pointer member type")?)
            .context("TUN pointer type")?;
        ensure!(
            btf.kind(at) == Some(2) && (!void || btf.u32_at(at + 8) == Some(0)),
            "TUN pointer field ABI"
        );
        found = Some(bits / 8);
    }
    found.context("TUN pointer field missing")
}
fn enum_value(btf: &Btf<'_>, owner: &str, member: &str) -> anyhow::Result<u32> {
    let at = btf.find_type(6, owner).context("TUN iterator enum")?;
    let len = btf.u32_at(at + 4).context("TUN enum length")? & 0xffff;
    for index in 0..len as usize {
        let pos = at + 12 + index * 8;
        if btf.string(btf.u32_at(pos).context("TUN enumerator name")?) == Some(member) {
            return btf.u32_at(pos + 4).context("TUN enumerator value");
        }
    }
    anyhow::bail!("TUN enum member {owner}.{member} missing")
}
fn bitfield(btf: &Btf<'_>, root: &str, name: &str) -> anyhow::Result<(u32, u32)> {
    fn find(btf: &Btf<'_>, owner: usize, name: &str, depth: u8) -> Option<(u32, u32)> {
        if depth == 8 || !matches!(btf.kind(owner)?, 4 | 5) {
            return None;
        }
        let info = btf.u32_at(owner + 4)?;
        let mut found = None;
        for index in 0..(info & 0xffff) as usize {
            let pos = owner + 12 + index * 12;
            let field_name = btf.string(btf.u32_at(pos)?)?;
            let id = btf.u32_at(pos + 4)?;
            let raw = btf.u32_at(pos + 8)?;
            let bits = if info >> 31 != 0 { raw & 0xffffff } else { raw };
            let value = if field_name == name && info >> 31 != 0 && raw >> 24 == 1 {
                Some((bits / 8, 1 << (bits % 8)))
            } else if field_name.is_empty() && bits % 8 == 0 {
                find(btf, btf.resolve_composite(id)?, name, depth + 1)
                    .and_then(|(offset, mask)| Some((offset.checked_add(bits / 8)?, mask)))
            } else {
                None
            };
            if let Some(value) = value {
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
        found
    }
    find(
        btf,
        btf.find_type(4, root).context("TUN bitfield owner")?,
        name,
        0,
    )
    .with_context(|| format!("actual TUN bitfield {root}.{name}"))
}

#[repr(C)]
#[derive(Default)]
struct BtfInfo {
    data: u64,
    size: u32,
    id: u32,
    name: u64,
    name_len: u32,
    kernel: u32,
}
fn btf_info(fd: BorrowedFd<'_>, value: &mut BtfInfo) -> anyhow::Result<()> {
    #[repr(C)]
    struct Attr {
        fd: u32,
        length: u32,
        info: u64,
    }
    let mut attr = Attr {
        fd: fd.as_raw_fd() as u32,
        length: size_of::<BtfInfo>() as u32,
        info: value as *mut BtfInfo as u64,
    };
    sys::bpf(15, &mut attr)?;
    ensure!(
        attr.length as usize >= size_of::<BtfInfo>(),
        "short running module BTF information"
    );
    Ok(())
}
fn module_btf_fd(name: &str) -> anyhow::Result<OwnedFd> {
    #[repr(C)]
    struct Id {
        start: u32,
        next: u32,
        flags: u32,
    }
    let mut start = 0;
    for _ in 0..4096 {
        let mut id = Id {
            start,
            next: 0,
            flags: 0,
        };
        match sys::bpf(23, &mut id) {
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => break,
            Err(error) => return Err(error.into()),
        }
        ensure!(id.next > start, "TUN BTF inventory failed to advance");
        start = id.next;
        let mut get = Id {
            start,
            next: 0,
            flags: 0,
        };
        let fd = match sys::bpf(19, &mut get) {
            Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        let mut bytes = [0u8; 256];
        let mut info = BtfInfo {
            name: bytes.as_mut_ptr() as u64,
            name_len: bytes.len() as u32,
            ..Default::default()
        };
        btf_info(fd.as_fd(), &mut info)?;
        let len = bytes
            .iter()
            .position(|&x| x == 0)
            .context("unterminated kernel BTF name")?;
        if &bytes[..len] == name.as_bytes() {
            ensure!(
                info.id == start && info.kernel == 1,
                "TUN BTF is not the running module"
            );
            return Ok(fd);
        }
    }
    anyhow::bail!("running TUN module BTF FD unavailable")
}
fn verify_module(fd: BorrowedFd<'_>, data: &[u8]) -> anyhow::Result<()> {
    let mut observed = Vec::new();
    observed.try_reserve_exact(data.len())?;
    observed.resize(data.len(), 0);
    let mut info = BtfInfo {
        data: observed.as_mut_ptr() as u64,
        size: u32::try_from(observed.len())?,
        ..Default::default()
    };
    btf_info(fd, &mut info)?;
    ensure!(
        info.kernel == 1 && info.size as usize == data.len() && observed == data,
        "module BTF FD differs from running sysfs BTF"
    );
    Ok(())
}
