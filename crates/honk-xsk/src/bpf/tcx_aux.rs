//! FD-owned TCX gateway links and the terminal guard on each private TUN.

use super::attachment::LinkUpdateAttr;
use super::gateway::{create_with_flags, lookup, update};
use super::*;
use crate::topology::{AuxLinkInfo, AuxLinkWatch};
use aya_obj::generated::{BPF_F_AFTER, BPF_F_BEFORE, BPF_F_LINK, BPF_F_RDONLY_PROG};
use honk_ebpf_common::xdp_gateway::{GatewayReason, HOST_PRIVATE_DELAY_NS, HOST_SKB_CHARGE_MAX};
use honk_netstack::{MemoryBudget, MemoryReservation};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const OUTER_SLOT: i32 = 0;
pub(super) const INNER_SLOT: i32 = 1;
const TCX_INGRESS: u32 = 46;
const TCX_EGRESS: u32 = 47;
const SCHED_CLS: u32 = 3;
const TCX_NEXT: i32 = -1;
const TCX_DROP: i32 = 2;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_QUERY: u32 = 16;
const BPF_LINK_TYPE_TCX: u32 = 11;
const BPF_MAP_FREEZE: u32 = 22;
const BPF_LINK_DETACH: u32 = 34;

fn namespace_identity() -> io::Result<(u64, u64)> {
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    Ok((namespace.dev(), namespace.ino()))
}

/// A fresh binding owns both netdevice references. NETDEV_UNREGISTER invalidates the old slots.
pub struct AuxDevicePair {
    devices: OwnedFd,
    gate: OwnedFd,
    scratch: OwnedFd,
    outer: u32,
    inner: u32,
    namespace: (u64, u64),
    broadcasts: Option<Box<HostBroadcasts>>,
    _memory: MemoryReservation,
}

impl AuxDevicePair {
    pub fn new(outer: u32, inner: u32, root: &Arc<MemoryBudget>) -> io::Result<Self> {
        Self::create(outer, inner, root, false)
    }

    pub fn new_host(outer: u32, inner: u32, root: &Arc<MemoryBudget>) -> io::Result<Self> {
        Self::create(outer, inner, root, true)
    }

    fn create(outer: u32, inner: u32, root: &Arc<MemoryBudget>, host: bool) -> io::Result<Self> {
        validate_ifindex(outer)?;
        validate_ifindex(inner)?;
        if outer == inner {
            return Err(invalid_data("auxiliary devices must be distinct"));
        }
        let devices = create_map(14, 4, 2, b"honk_aux_devs")?;
        update(devices.as_fd(), &OUTER_SLOT, &outer, 0)?;
        update(devices.as_fd(), &INNER_SLOT, &inner, 0)?;
        bpf(BPF_MAP_FREEZE, &mut (devices.as_raw_fd() as u32))?;
        let gate = create_with_flags::<u32, u32>(2, 1, b"honk_aux_gate", -1, BPF_F_RDONLY_PROG)?;
        let scratch = create_map(6, size_of::<[u64; 64]>() as u32, 1, b"honk_aux_tmp")?;
        let bytes = [&devices, &gate, &scratch].into_iter().try_fold(
            size_of::<Self>() + 2 * size_of::<usize>(),
            |n, fd| {
                n.checked_add(kernel_memory_bytes(fd.as_fd())?)
                    .ok_or_else(|| invalid_data("auxiliary map reservation overflow"))
            },
        )?;
        let memory = root
            .reserve(bytes)
            .ok_or_else(|| io::Error::other("auxiliary device map memory capacity"))?;
        let pair = Self {
            devices,
            gate,
            scratch,
            outer,
            broadcasts: if host {
                Some(Box::new(HostBroadcasts::new(root)?))
            } else {
                None
            },
            inner,
            _memory: memory,
            namespace: namespace_identity()?,
        };
        pair.verify()?;
        Ok(pair)
    }

    pub fn host_broadcasts_fd(&self) -> io::Result<BorrowedFd<'_>> {
        self.broadcasts
            .as_ref()
            .map(|bank| bank.root.as_fd())
            .ok_or_else(|| invalid_data("Host broadcasts require a Host binding"))
    }

    pub fn replace_host_broadcasts(&self, addresses: &[Ipv4Addr]) -> io::Result<()> {
        let bank = self
            .broadcasts
            .as_ref()
            .ok_or_else(|| invalid_data("Host broadcasts require a Host binding"))?;
        self.verify()?;
        let result = bank.replace(addresses);
        self.verify()?;
        result
    }

    pub fn suspend_host_broadcasts(&self) -> io::Result<()> {
        let bank = self
            .broadcasts
            .as_ref()
            .ok_or_else(|| invalid_data("Host broadcasts require a Host binding"))?;
        self.verify()?;
        let mut current = bank
            .current
            .lock()
            .map_err(|_| invalid_data("Host broadcast update lock poisoned"))?;
        bank.withdraw(&mut current)?;
        self.verify()
    }

    pub fn verify(&self) -> io::Result<()> {
        for (slot, index) in [(OUTER_SLOT, self.outer), (INNER_SLOT, self.inner)] {
            match lookup::<_, u32>(self.devices.as_fd(), &slot)? {
                Some(actual) if actual == index => (),
                None => return Err(io::Error::from_raw_os_error(libc::ENODEV)),
                Some(_) => return Err(invalid_data("auxiliary device slot changed")),
            }
        }
        Ok(())
    }

    pub fn inner_gone(&self) -> io::Result<bool> {
        Ok(lookup::<_, u32>(self.devices.as_fd(), &INNER_SLOT)?.is_none())
    }

    pub fn unavailable(&self) -> io::Result<bool> {
        if namespace_identity()? != self.namespace {
            return Err(invalid_data(
                "auxiliary availability checked in foreign namespace",
            ));
        }
        let present = || match self.verify() {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ENODEV) => Ok(false),
            Err(e) => Err(e),
        };
        if !present()? {
            return Ok(true);
        }
        let up = crate::topology::auxiliary_up(self.outer);
        if !present()? {
            return Ok(true);
        }
        up.map(|up| !up)
    }

    pub fn set_open(&self, open: bool) -> io::Result<()> {
        if open {
            self.verify()?;
        }
        let value = u32::from(open);
        update(self.gate.as_fd(), &0u32, &value, 0)?;
        self.verify_gate(value)
    }

    pub fn verify_open(&self) -> io::Result<()> {
        self.verify()?;
        self.verify_gate(1)
    }

    fn verify_gate(&self, value: u32) -> io::Result<()> {
        if lookup(self.gate.as_fd(), &0u32)? != Some(value) {
            return Err(invalid_data("auxiliary gate readback changed"));
        }
        Ok(())
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 3] {
        [
            self.devices.as_fd(),
            self.gate.as_fd(),
            self.scratch.as_fd(),
        ]
    }

    pub fn outer_ifindex(&self) -> u32 {
        self.outer
    }
    pub fn device_fd(&self) -> RawFd {
        self.devices.as_raw_fd()
    }
    pub fn gate_fd(&self) -> RawFd {
        self.gate.as_raw_fd()
    }
    pub fn scratch_fd(&self) -> RawFd {
        self.scratch.as_raw_fd()
    }
}

struct BroadcastSet {
    addresses: [Ipv4Addr; crate::topology::MAX_BROADCASTS],
    count: usize,
    id: u32,
}

struct HostBroadcasts {
    root: OwnedFd,
    current: std::sync::Mutex<BroadcastSet>,
    // Preallocated hash maps have a fixed footprint. Reserve both generations here,
    // including their FDs, so an active binding can always stage its next snapshot.
    inner_bytes: usize,
    _memory: MemoryReservation,
}

impl HostBroadcasts {
    fn inner(addresses: &[Ipv4Addr]) -> io::Result<(OwnedFd, u32)> {
        let fd = create_with_flags::<[u8; 4], u32>(
            1,
            crate::topology::MAX_BROADCASTS as u32,
            b"honk_host_bcast",
            -1,
            BPF_F_RDONLY_PROG,
        )?;
        for address in addresses {
            update(fd.as_fd(), &address.octets(), &1u32, 1)?;
        }
        bpf(BPF_MAP_FREEZE, &mut (fd.as_raw_fd() as u32))?;
        let id = gateway::map_id(fd.as_fd())?;
        Ok((fd, id))
    }

    fn new(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let (inner, id) = Self::inner(&[])?;
        // ARRAY_OF_MAPS already permits only lookups from BPF; it rejects program-access flags.
        let root = create_with_flags::<u32, u32>(12, 1, b"honk_bcast_root", inner.as_raw_fd(), 0)?;
        update(root.as_fd(), &0u32, &inner.as_raw_fd(), 0)?;
        if lookup(root.as_fd(), &0u32)? != Some(id) {
            return Err(invalid_data("Host broadcast root initialization failed"));
        }
        let inner_bytes = kernel_memory_bytes(inner.as_fd())?;
        let root_bytes = kernel_memory_bytes(root.as_fd())?;
        let page = kernel_page_size()?;
        let bytes = inner_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(root_bytes))
            .and_then(|n| n.checked_add(3 * page + size_of::<Self>()))
            .ok_or_else(|| invalid_data("Host broadcast memory overflow"))?;
        let memory = budget
            .reserve(bytes)
            .ok_or_else(|| io::Error::other("Host broadcast map capacity"))?;
        Ok(Self {
            root,
            current: std::sync::Mutex::new(BroadcastSet {
                addresses: [Ipv4Addr::UNSPECIFIED; crate::topology::MAX_BROADCASTS],
                count: 0,
                id,
            }),
            inner_bytes,
            _memory: memory,
        })
    }

    fn replace(&self, addresses: &[Ipv4Addr]) -> io::Result<()> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| invalid_data("Host broadcast update lock poisoned"))?;
        let result = self.publish(&mut current, addresses);
        if let Err(error) = result {
            self.withdraw(&mut current)?;
            return Err(io::Error::new(io::ErrorKind::WouldBlock, error));
        }
        Ok(())
    }

    fn withdraw(&self, current: &mut BroadcastSet) -> io::Result<()> {
        // The incumbent classifier drops ambiguous IPv4 while the inner slot is absent.
        let key = 0u32;
        if let Err(delete) = bpf(
            BPF_MAP_DELETE_ELEM,
            &mut MapElemAttr {
                map_fd: self.root.as_raw_fd() as u32,
                reserved: 0,
                key: &key as *const _ as u64,
                value: 0,
                flags: 0,
            },
        ) && delete.raw_os_error() != Some(libc::ENOENT)
        {
            return Err(delete);
        }
        if lookup::<_, u32>(self.root.as_fd(), &key)?.is_some() {
            return Err(invalid_data("Host broadcast root withdrawal failed"));
        }
        current.id = 0;
        Ok(())
    }

    fn publish(&self, current: &mut BroadcastSet, addresses: &[Ipv4Addr]) -> io::Result<()> {
        if addresses.len() > crate::topology::MAX_BROADCASTS
            || addresses.windows(2).any(|a| a[0] >= a[1])
        {
            return Err(invalid_data("invalid Host broadcast inventory"));
        }
        if lookup(self.root.as_fd(), &0u32)? != (current.id != 0).then_some(current.id) {
            return Err(invalid_data("Host broadcast root changed"));
        }
        if current.id != 0 && current.addresses[..current.count] == *addresses {
            return Ok(());
        }
        let (inner, id) = Self::inner(addresses)?;
        if kernel_memory_bytes(inner.as_fd())? > self.inner_bytes {
            return Err(invalid_data("Host broadcast staging exceeds reservation"));
        }
        for address in addresses {
            if lookup::<_, u32>(inner.as_fd(), &address.octets())? != Some(1) {
                return Err(invalid_data("Host broadcast staging readback failed"));
            }
        }
        // Occupied map-in-map update waits for pre-existing non-sleepable BPF readers.
        // Keep this binding's writer lock through readback and reuse of the staging grant.
        update(self.root.as_fd(), &0u32, &inner.as_raw_fd(), 0)?;
        if lookup(self.root.as_fd(), &0u32)? != Some(id) {
            return Err(invalid_data("Host broadcast replacement readback failed"));
        }
        current.addresses[..addresses.len()].copy_from_slice(addresses);
        current.count = addresses.len();
        current.id = id;
        Ok(())
    }
}

#[repr(C)]
#[derive(Default)]
struct TcxInfo {
    kind: u32,
    id: u32,
    program: u32,
    padding: u32,
    ifindex: u32,
    attach_type: u32,
}

struct Chain {
    // Linux BPF_MPROG_MAX bounds a TCX chain. Fetch both columns under one RTNL acquisition.
    programs: [u32; 64],
    links: [u32; 64],
    len: usize,
    revision: u64,
}

impl Chain {
    fn read(index: u32, attach_type: u32) -> io::Result<Self> {
        #[repr(C)]
        #[derive(Default)]
        struct Query {
            target: u32,
            attach_type: u32,
            flags: u32,
            attach_flags: u32,
            programs: u64,
            count: u32,
            padding: u32,
            program_flags: u64,
            links: u64,
            link_flags: u64,
            revision: u64,
        }
        let mut chain = Self {
            programs: [0; 64],
            links: [0; 64],
            len: 0,
            revision: 0,
        };
        let mut query = Query {
            target: index,
            attach_type,
            programs: chain.programs.as_mut_ptr() as u64,
            links: chain.links.as_mut_ptr() as u64,
            count: chain.programs.len() as u32,
            ..Default::default()
        };
        bpf(BPF_PROG_QUERY, &mut query)?;
        chain.len = query.count as usize;
        chain.revision = query.revision;
        if chain.len > chain.programs.len() || chain.revision == 0 {
            return Err(invalid_data("invalid TCX chain readback"));
        }
        Ok(chain)
    }

    fn entries(&self) -> impl DoubleEndedIterator<Item = (u32, u32)> + '_ {
        self.programs[..self.len]
            .iter()
            .copied()
            .zip(self.links[..self.len].iter().copied())
    }
}

fn program_id(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut info = ProgInfo::default();
    object_info(fd, &mut info)?;
    if info.kind != SCHED_CLS || info.id == 0 {
        return Err(invalid_data("foreign TCX program"));
    }
    Ok(info.id)
}

pub(super) fn kernel_page_size() -> io::Result<usize> {
    // SAFETY: sysconf has no pointer arguments.
    usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|p| p.is_power_of_two())
        .ok_or_else(|| invalid_data("invalid kernel page size"))
}

/// Charge the same packet limit for the single leaf qdisc and TUN read ring.
pub struct HostFifo {
    slots: u32,
    _memory: MemoryReservation,
}

impl HostFifo {
    pub fn reserve(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let page = kernel_page_size()?;
        // The outer classifier bounds truesize before the private qdisc. The final
        // filter rechecks it before tun_net_xmit. A zerocopy skb may additionally
        // unclone its head and copy <=64 KiB of paged data after the final filter.
        // The bounded head (including aligned shared_info) fits the same slab size.
        let unit = HOST_SKB_CHARGE_MAX as usize;
        let per_slot = (3 * unit)
            .checked_add(page.max(65536))
            .ok_or_else(|| invalid_data("Host FIFO charge overflow"))?;
        // The freshly allocated default 500-pointer queue and its replacement may coexist.
        let rings = (500 * size_of::<usize>()).next_multiple_of(page) + page;
        for slots in (1..=8u32).rev() {
            let bytes = per_slot
                .checked_mul(slots as usize)
                .and_then(|bytes| bytes.checked_add(rings))
                .ok_or_else(|| invalid_data("Host FIFO capacity overflow"))?;
            if let Some(memory) = budget.reserve(bytes) {
                return Ok(Self {
                    slots,
                    _memory: memory,
                });
            }
        }
        Err(io::Error::other(
            "one private Host qdisc and TUN read slot exceed capture memory capacity",
        ))
    }

    pub fn slots(&self) -> u32 {
        self.slots
    }
}

fn kernel_reservation(include_link: bool, include_chain: bool) -> io::Result<usize> {
    // TCX link fdinfo has no memlock. Reserve each live allocation separately, with room for
    // slab bookkeeping and the fdtable entry, rounded up to the running kernel's page size.
    let [link, entry, file] = ct::tcx_struct_sizes()?;
    let page = kernel_page_size()?;
    [
        (include_link, link),
        (include_link, file),
        (include_chain, entry),
    ]
    .into_iter()
    .filter(|(needed, _)| *needed)
    .try_fold(0usize, |sum, (_, size)| {
        size.checked_add(2 * size_of::<usize>())
            .and_then(|v| v.checked_next_multiple_of(page))
            .and_then(|n| sum.checked_add(n))
            .ok_or_else(|| invalid_data("TCX memory reservation overflow"))
    })
}

/// An unpinned link. All updates name this FD and the expected old program FD.
pub struct AuxTcxLink {
    fd: OwnedFd,
    index: u32,
    attach_type: u32,
    id: u32,
    guard: Option<u32>,
}

impl AuxTcxLink {
    /// Attach the closed binding and return the live link with its kernel reservation.
    pub fn outer(
        pair: &AuxDevicePair,
        program: BorrowedFd<'_>,
        root: &Arc<MemoryBudget>,
    ) -> io::Result<(Self, MemoryReservation)> {
        Self::outer_at(pair, program, root, TCX_INGRESS)
    }

    pub fn host_egress(
        pair: &AuxDevicePair,
        program: BorrowedFd<'_>,
        root: &Arc<MemoryBudget>,
    ) -> io::Result<(Self, MemoryReservation)> {
        Self::outer_at(pair, program, root, TCX_EGRESS)
    }

    fn outer_at(
        pair: &AuxDevicePair,
        program: BorrowedFd<'_>,
        root: &Arc<MemoryBudget>,
        attach_type: u32,
    ) -> io::Result<(Self, MemoryReservation)> {
        if pair.namespace != namespace_identity()? {
            return Err(invalid_data("auxiliary TCX attach in foreign namespace"));
        }
        pair.verify()?;
        pair.verify_gate(0)?;
        ct::tcx_struct_sizes_accounted(root)?;
        let memory = root
            .reserve(kernel_reservation(true, true)?)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "auxiliary outer TCX link capacity",
                )
            })?;
        let (neutral, _) = constant_program(TCX_NEXT, b"honk_aux_anchor", attach_type)?;
        let neutral_memory = root
            .reserve(kernel_memory_bytes(neutral.as_fd())?)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "auxiliary outer TCX anchor capacity",
                )
            })?;
        let staging = (neutral, neutral_memory);
        let index = pair.outer_ifindex();
        let chain = Chain::read(index, attach_type)?;
        // An ifindex can be recycled between the pair lookup and BPF_LINK_CREATE.
        let link = Self::attach(
            index,
            attach_type,
            staging.0.as_fd(),
            BPF_F_AFTER,
            0,
            chain.revision,
            None,
        )?;
        link.activate_outer(pair, staging.0.as_fd(), program)?;
        Ok((link, memory))
    }

    fn activate_outer(
        &self,
        pair: &AuxDevicePair,
        neutral: BorrowedFd<'_>,
        program: BorrowedFd<'_>,
    ) -> io::Result<()> {
        // Live slots after attaching prove the neutral link could only have targeted the old
        // pair. The replacement syscall then uses that link's FD regardless of ifindex reuse.
        pair.verify()?;
        pair.verify_gate(0)?;
        self.replace(neutral, program)?;
        pair.verify()
    }

    fn attach(
        index: u32,
        attach_type: u32,
        program: BorrowedFd<'_>,
        flags: u32,
        relative: u32,
        revision: u64,
        guard: Option<u32>,
    ) -> io::Result<Self> {
        #[repr(C)]
        struct Create {
            program: u32,
            index: u32,
            attach_type: u32,
            flags: u32,
            relative: u32,
            padding: u32,
            revision: u64,
        }
        let expected = program_id(program)?;
        let fd = bpf_fd(
            BPF_LINK_CREATE,
            &mut Create {
                program: program.as_raw_fd() as u32,
                index,
                attach_type,
                flags,
                relative,
                padding: 0,
                revision,
            },
        )?;
        let mut info = TcxInfo::default();
        object_info(fd.as_fd(), &mut info)?;
        let link = Self {
            fd,
            index,
            attach_type,
            id: info.id,
            guard,
        };
        link.verify(expected)?;
        Ok(link)
    }

    pub fn verify_fd(&self, expected: u32) -> io::Result<()> {
        let mut info = TcxInfo::default();
        object_info(self.fd.as_fd(), &mut info)?;
        if info.kind != BPF_LINK_TYPE_TCX
            || self.id == 0
            || info.id != self.id
            || info.program != expected
            || info.ifindex != self.index
            || info.attach_type != self.attach_type
        {
            return Err(invalid_data("auxiliary TCX link identity changed"));
        }
        Ok(())
    }

    pub fn verify(&self, expected: u32) -> io::Result<()> {
        self.verify_fd(expected)?;
        let chain = Chain::read(self.index, self.attach_type)?;
        let valid = match self.guard {
            None => chain.entries().next_back() == Some((expected, self.id)),
            Some(guard) => chain.entries().eq([(expected, self.id), (guard, 0)]),
        };
        if !valid {
            return Err(invalid_data("auxiliary TCX chain changed"));
        }
        Ok(())
    }

    pub fn replace(&self, old: BorrowedFd<'_>, new: BorrowedFd<'_>) -> io::Result<()> {
        self.verify(program_id(old)?)?;
        let new_id = program_id(new)?;
        bpf(
            BPF_LINK_UPDATE,
            &mut LinkUpdateAttr {
                link_fd: self.fd.as_raw_fd() as u32,
                new_prog_fd: new.as_raw_fd() as u32,
                flags: BPF_F_REPLACE,
                old_prog_fd: old.as_raw_fd() as u32,
            },
        )?;
        self.verify(new_id)
    }

    pub fn detach(&self) -> io::Result<()> {
        bpf(BPF_LINK_DETACH, &mut (self.fd.as_raw_fd() as u32)).map(|_| ())
    }

    /// Conservative reservation for the FD-owned link and its chain. Program maps are charged separately.
    pub fn memory_bytes(&self) -> io::Result<usize> {
        kernel_reservation(true, self.guard.is_none())
    }
}

impl AsFd for AuxTcxLink {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn verify_private_tun(fd: BorrowedFd<'_>, index: u32) -> io::Result<()> {
    // SAFETY: TUNGETIFF fills the supplied ifreq on a live TUN FD.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the ioctl wrote ifru_flags and a terminated kernel device name.
    let flags = i32::from(unsafe { req.ifr_ifru.ifru_flags } as u16);
    let required = libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR;
    let prohibited =
        libc::IFF_TAP | libc::IFF_PERSIST | libc::IFF_MULTI_QUEUE | libc::IFF_DETACH_QUEUE;
    if flags & (required | prohibited) != required
        || !req.ifr_name.contains(&0)
        || unsafe { libc::if_nametoindex(req.ifr_name.as_ptr()) } != index
    {
        return Err(invalid_data(
            "guard requires the owned single-queue nonpersistent TUN",
        ));
    }
    // SAFETY: TUNGETDEVNETNS returns a fresh descriptor identifying this TUN's current namespace.
    let raw = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETDEVNETNS) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let net = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) }).metadata()?;
    if (net.dev(), net.ino()) != namespace_identity()? {
        return Err(invalid_data(
            "auxiliary TUN lives in a foreign network namespace",
        ));
    }
    Ok(())
}

fn tcx_program(builder: Builder, name: &[u8], attach_type: u32) -> io::Result<(OwnedFd, u32)> {
    load_typed_program(
        &builder.finish()?,
        name,
        &mut [0u8; 8192],
        SCHED_CLS,
        attach_type,
    )
}

fn constant_program(verdict: i32, name: &[u8], attach_type: u32) -> io::Result<(OwnedFd, u32)> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_K, 0, 0, 0, verdict));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    tcx_program(b, name, attach_type)
}

fn host_delay_filter(
    stats: BorrowedFd<'_>,
    admitted: BorrowedFd<'_>,
    ct: &HostConntrack,
) -> io::Result<Program> {
    const SUB_X: u8 = 0x1f;
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 6, 1, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 6, 32, 0)); // __sk_buff.priority: valid bit and admission ns[62:32]
    b.jump(Insn::new(JSET_K, 7, 0, 0, i32::MIN), Label::Selected);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::CountDrop);
    b.label(Label::Selected);
    b.emit(Insn::new(AND_K, 7, 0, 0, i32::MAX));
    b.emit(Insn::new(LSH_K, 7, 0, 0, 32));
    b.emit(Insn::new(LDX_W, 0, 6, 8, 0)); // __sk_buff.mark: admission ns[31:0]
    b.emit(Insn::new(ADD_X, 7, 0, 0, 0));
    b.jump(Insn::new(JEQ_K, 7, 0, 0, 0), Label::CountDrop);
    b.emit(Insn::new(CALL, 0, 0, 0, 5)); // bpf_ktime_get_ns
    b.jump(Insn::new(JGT_X, 7, 0, 0, 0), Label::CountDrop);
    b.emit(Insn::new(SUB_X, 0, 7, 0, 0));
    b.emit(Insn::new(LD_MAP, 1, 0, 0, HOST_PRIVATE_DELAY_NS as i32)); // ldimm64, no pseudo map
    b.emit(Insn::new(0, 0, 0, 0, (HOST_PRIVATE_DELAY_NS >> 32) as i32));
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::CountDrop);
    b.emit(Insn::new(LDX_W, 0, 6, 0, 0));
    b.jump(Insn::new(JGT_K, 0, 0, 0, 65536), Label::Malformed);
    b.emit(Insn::new(MOV_X, 1, 6, 0, 0));
    b.emit(Insn::new(CALL, 0, 2, 0, ct.cast)); // typed sk_buff, validated kernel offsets
    b.emit(Insn::new(LDX_W, 1, 0, ct.skb_end, 0));
    b.jump(
        Insn::new(JGT_K, 1, 0, 0, ct.skb_end_limit()?),
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_W, 1, 0, ct.skb_truesize, 0));
    b.jump(
        Insn::new(JGT_K, 1, 0, 0, HOST_SKB_CHARGE_MAX as i32),
        Label::Malformed,
    );
    // Count even if a later ptr_ring insertion fails; a drain may then require EAGAIN.
    b.emit(Insn::new(ST_W, 10, 0, -4, 0));
    b.count(admitted.as_raw_fd());
    b.emit(Insn::new(LDX_W, 0, 6, 0, 0)); // return full skb length
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Malformed);
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        -4,
        GatewayReason::HostQueueCapacity as i32,
    ));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    b.label(Label::CountDrop);
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        -4,
        GatewayReason::HostLatePacket as i32,
    ));
    b.label(Label::Pass);
    b.count(stats.as_raw_fd());
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

struct HostDelayFilter {
    _program: OwnedFd,
    admitted: OwnedFd,
    scratch: std::sync::Mutex<Box<[u64]>>,
    _memory: MemoryReservation,
}

/// A device-owned terminal on a newly created private TUN survives process exit until unregister.
pub struct AuxTunGuard {
    index: u32,
    program: OwnedFd,
    id: u32,
    delay_filter: Option<Box<HostDelayFilter>>,
}

impl AuxTunGuard {
    pub fn install(inner: u32, tun: BorrowedFd<'_>, root: &Arc<MemoryBudget>) -> io::Result<Self> {
        validate_ifindex(inner)?;
        verify_private_tun(tun, inner)?;
        ct::tcx_struct_sizes_accounted(root)?;
        let chain = Chain::read(inner, TCX_INGRESS)?;
        if chain.len != 0 {
            return Err(invalid_data(
                "private auxiliary TUN has foreign TCX ingress",
            ));
        }
        // Only an FD-owned NEXT may be installed by ifindex alone. The durable operation names
        // this exact link after checking the TUN FD again, so ifindex reuse cannot inherit SHOT.
        let (neutral, neutral_id) = constant_program(TCX_NEXT, b"honk_aux_anchor", TCX_INGRESS)?;
        let stage_bytes = kernel_reservation(true, true)?
            .checked_add(kernel_memory_bytes(neutral.as_fd())?)
            .ok_or_else(|| invalid_data("auxiliary guard staging capacity overflow"))?;
        let _stage = root
            .reserve(stage_bytes)
            .ok_or_else(|| io::Error::other("auxiliary guard staging capacity"))?;
        let anchor = AuxTcxLink::attach(
            inner,
            TCX_INGRESS,
            neutral.as_fd(),
            BPF_F_AFTER,
            0,
            chain.revision,
            None,
        )?;
        verify_private_tun(tun, inner)?;
        let chain = Chain::read(inner, TCX_INGRESS)?;
        if !chain.entries().eq([(neutral_id, anchor.id)]) {
            return Err(invalid_data("private auxiliary TUN anchor changed"));
        }
        let (program, id) = constant_program(TCX_DROP, b"honk_aux_stop", TCX_INGRESS)?;
        let _terminal = root
            .reserve(kernel_memory_bytes(program.as_fd())?)
            .ok_or_else(|| io::Error::other("auxiliary terminal program capacity"))?;
        #[repr(C)]
        struct Attach {
            target: u32,
            program: u32,
            attach_type: u32,
            flags: u32,
            replace: u32,
            relative: u32,
            revision: u64,
        }
        bpf(
            BPF_PROG_ATTACH,
            &mut Attach {
                target: inner,
                program: program.as_raw_fd() as u32,
                attach_type: TCX_INGRESS,
                flags: BPF_F_AFTER | BPF_F_LINK,
                replace: 0,
                relative: anchor.fd.as_raw_fd() as u32,
                revision: chain.revision,
            },
        )?;
        anchor.detach()?;
        let guard = Self {
            index: inner,
            program,
            id,
            delay_filter: None,
        };
        if !Chain::read(inner, TCX_INGRESS)?.entries().eq([(id, 0)]) {
            return Err(invalid_data("private auxiliary TUN guard install changed"));
        }
        Ok(guard)
    }

    /// The TUN owns its own filter reference until unregister. The caller keeps this
    /// guard alongside the exclusive TUN FD, including across activation failures.
    pub fn install_host_delay_filter(
        &mut self,
        tun: BorrowedFd<'_>,
        pair: &AuxDevicePair,
        maps: &GatewayMaps,
        root: &Arc<MemoryBudget>,
        ct: &HostConntrack,
    ) -> io::Result<()> {
        if self.delay_filter.is_some()
            || pair.inner != self.index
            || namespace_identity()? != pair.namespace
        {
            return Err(invalid_data(
                "Host delay filter requires a fresh owned private TUN",
            ));
        }
        pair.verify()?;
        pair.verify_gate(0)?;
        verify_private_tun(tun, self.index)?;
        self.verify()?;
        if Chain::read(self.index, TCX_EGRESS)?.len != 0 {
            return Err(invalid_data("private Host TUN has foreign TCX egress"));
        }
        let admitted = create_with_flags::<u32, u64>(6, 1, b"honk_host_reads", -1, 0)?;
        let (fd, _) = load_typed_program(
            &host_delay_filter(maps.stats_fd(), admitted.as_fd(), ct)?,
            b"honk_host_age",
            &mut [0; 8192],
            1,
            0,
        )?;
        let cpus = gateway::possible_cpu_count(&std::fs::read_to_string(
            "/sys/devices/system/cpu/possible",
        )?)?;
        // Program/map fdinfo excludes their two files and the TUN's tun_prog RCU wrapper.
        let objects = kernel_page_size()?
            .checked_mul(3)
            .ok_or_else(|| invalid_data("Host TUN filter object size overflow"))?;
        let bytes = cpus
            .checked_mul(size_of::<u64>())
            .and_then(|n| n.checked_add(size_of::<HostDelayFilter>()))
            .and_then(|n| n.checked_add(objects))
            .ok_or_else(|| invalid_data("Host TUN filter scratch size overflow"))?;
        let kernel_bytes = kernel_memory_bytes(fd.as_fd())?
            .checked_add(kernel_memory_bytes(admitted.as_fd())?)
            .and_then(|n| n.checked_add(bytes))
            .ok_or_else(|| invalid_data("Host TUN filter memory overflow"))?;
        let charge = root
            .reserve(kernel_bytes)
            .ok_or_else(|| io::Error::other("Host TUN delay filter memory capacity"))?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(cpus)
            .map_err(|_| io::Error::other("Host TUN filter counter scratch"))?;
        scratch.resize(cpus, 0u64);
        // SAFETY: Linux copies one int and retains a reference on this exact open TUN.
        if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETFILTEREBPF, &fd.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.delay_filter = Some(Box::new(HostDelayFilter {
            _program: fd,
            admitted,
            scratch: std::sync::Mutex::new(scratch.into_boxed_slice()),
            _memory: charge,
        }));
        pair.verify()
    }

    /// Success count before the ring for this binding only. Per-CPU values may advance
    /// during the read. A post-grace read includes every pre-grace filter completion.
    pub fn admitted_records(&self) -> io::Result<u64> {
        let filter = self
            .delay_filter
            .as_ref()
            .ok_or_else(|| invalid_data("Host TUN filter not installed"))?;
        let mut values = filter
            .scratch
            .lock()
            .map_err(|_| invalid_data("Host TUN counter lock poisoned"))?;
        let key = 0u32;
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut MapElemAttr {
                map_fd: filter.admitted.as_raw_fd() as u32,
                reserved: 0,
                key: &key as *const _ as u64,
                value: values.as_mut_ptr() as u64,
                flags: 0,
            },
        )?;
        values.iter().try_fold(0u64, |sum, n| {
            sum.checked_add(*n)
                .ok_or_else(|| invalid_data("Host TUN admission counter overflow"))
        })
    }

    pub fn verify(&self) -> io::Result<()> {
        let chain = Chain::read(self.index, TCX_INGRESS)?;
        if chain.entries().next_back() != Some((self.id, 0)) {
            return Err(invalid_data("private auxiliary TUN terminal changed"));
        }
        if self.delay_filter.is_some() && Chain::read(self.index, TCX_EGRESS)?.len != 0 {
            return Err(invalid_data(
                "private Host TUN acquired a foreign TCX egress hook",
            ));
        }
        Ok(())
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 1] {
        [self.program.as_fd()]
    }

    pub fn memory_bytes(&self) -> io::Result<usize> {
        kernel_reservation(false, true)?
            .checked_add(kernel_memory_bytes(self.program.as_fd())?)
            .ok_or_else(|| invalid_data("TCX guard reservation overflow"))
    }

    pub fn attach_return(&self, pair: &Arc<AuxDevicePair>) -> io::Result<AuxReturnLink> {
        self.attach_return_to(pair, false, None)
    }

    pub fn attach_host_return(
        &self,
        pair: &Arc<AuxDevicePair>,
        info: &AuxLinkInfo,
        watch: &AuxLinkWatch,
        name: &str,
    ) -> io::Result<AuxReturnLink> {
        verify_host_device(pair, watch, name, info)?;
        let target = if info.is_l2 {
            Some(HostMac::new(info)?)
        } else {
            None
        };
        self.attach_return_to(pair, true, target)
    }

    fn attach_return_to(
        &self,
        pair: &Arc<AuxDevicePair>,
        ingress: bool,
        mac: Option<HostMac>,
    ) -> io::Result<AuxReturnLink> {
        pair.verify()?;
        if pair.inner != self.index || pair.namespace != namespace_identity()? {
            return Err(invalid_data("return link requires its owned device pair"));
        }
        pair.verify_gate(0)?;
        let chain = Chain::read(self.index, TCX_INGRESS)?;
        if !chain.entries().eq([(self.id, 0)]) {
            return Err(invalid_data("private TUN guard is not alone"));
        }
        let mut b = Builder::new();
        if mac.is_some() {
            b.emit(Insn::new(MOV_X, 9, 1, 0, 0)); // skb survives helper calls
        }
        b.emit(Insn::new(LDX_W, 6, 1, 40, 0));
        let mut load = |fd: RawFd, slot: i32, check: Insn| {
            b.emit(Insn::new(ST_W, 10, 0, -4, slot));
            b.map_fd(fd);
            b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
            b.emit(Insn::new(ADD_K, 2, 0, 0, -4));
            b.emit(Insn::new(CALL, 0, 0, 0, 1));
            b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
            b.emit(Insn::new(LDX_W, 0, 0, 0, 0));
            b.jump(check, Label::Drop);
        };
        load(pair.gate_fd(), 0, Insn::new(JNE_K, 0, 0, 0, 1));
        load(pair.device_fd(), INNER_SLOT, Insn::new(JNE_X, 0, 6, 0, 0));
        load(pair.device_fd(), OUTER_SLOT, Insn::new(JEQ_K, 0, 0, 0, 0));
        if let Some(target) = &mac {
            b.emit(Insn::new(MOV_X, 8, 0, 0, 0)); // verified outer ifindex
            ethernet_return_header(&mut b, target.fd.as_raw_fd());
            b.emit(Insn::new(MOV_X, 0, 8, 0, 0));
        }
        b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
        b.emit(Insn::new(MOV_K, 2, 0, 0, i32::from(ingress)));
        b.emit(Insn::new(CALL, 0, 0, 0, 23)); // bpf_redirect
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        b.label(Label::Drop);
        b.emit(Insn::new(MOV_K, 0, 0, 0, TCX_DROP));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        let (program, id) = tcx_program(b, b"honk_aux_return", TCX_INGRESS)?;
        let link = AuxTcxLink::attach(
            self.index,
            TCX_INGRESS,
            program.as_fd(),
            BPF_F_BEFORE,
            self.program.as_raw_fd() as u32,
            chain.revision,
            Some(self.id),
        )?;
        pair.verify()?;
        Ok(AuxReturnLink {
            link,
            program,
            id,
            pair: Arc::clone(pair),
            mac,
        })
    }
}

fn verify_host_device(
    pair: &AuxDevicePair,
    watch: &AuxLinkWatch,
    name: &str,
    info: &AuxLinkInfo,
) -> io::Result<()> {
    pair.verify()?;
    if pair.namespace != namespace_identity()? || pair.outer != info.ifindex || !info.up {
        return Err(invalid_data(
            "Host return requires its admitted device pair",
        ));
    }
    match watch.verify_host_outer(name, *info) {
        Ok(true) => (),
        Err(error) if error.kind() != io::ErrorKind::Unsupported => return Err(error),
        _ => return Err(io::Error::from_raw_os_error(libc::ENODEV)),
    }
    pair.verify()
}

struct HostMac {
    fd: OwnedFd,
    slot: NonNull<AtomicU64>,
    mtu: u32,
}

// SAFETY: the sole mapping remains live with this owner and is accessed only atomically.
unsafe impl Send for HostMac {}
unsafe impl Sync for HostMac {}

impl HostMac {
    fn new(info: &AuxLinkInfo) -> io::Result<Self> {
        let fd =
            create_with_flags::<u32, u64>(2, 1, b"honk_host_mac", -1, gateway::BPF_F_MMAPABLE)?;
        let slot = gateway::mmap_slots(fd.as_fd(), 1)?;
        let mac = Self {
            fd,
            slot,
            mtu: info.mtu,
        };
        mac.set(info.local_mac);
        Ok(mac)
    }

    fn set(&self, destination: [u8; 6]) {
        // One aligned 64-bit store and one aligned BPF load: neither reader can see
        // a mixed address. The trailing bytes start the fixed local source MAC.
        let [a, b, c, d, e, f] = destination;
        let word = u64::from_ne_bytes([a, b, c, d, e, f, 0x02, 0x68]);
        // SAFETY: the map's first slot is page aligned, initialized and live with self.
        unsafe { self.slot.as_ref() }.store(word, Ordering::Release);
    }
}

impl Drop for HostMac {
    fn drop(&mut self) {
        // SAFETY: this owner holds exactly the original one-slot mapping.
        unsafe { libc::munmap(self.slot.as_ptr().cast(), size_of::<AtomicU64>()) };
    }
}

fn ethernet_return_header(b: &mut Builder, mac: RawFd) {
    const LDX_DW: u8 = 0x79;
    const STX_DW: u8 = 0x7b;
    const STX_H: u8 = 0x6b;
    // skb->protocol is already in network order. Read it before moving any packet data.
    b.emit(Insn::new(LDX_W, 7, 9, 16, 0));
    b.jump(
        Insn::new(JEQ_K, 7, 0, 0, i32::from(0x0800u16.to_be())),
        Label::Selected,
    );
    b.jump(
        Insn::new(JNE_K, 7, 0, 0, i32::from(0x86ddu16.to_be())),
        Label::Drop,
    );
    b.label(Label::Selected);
    b.emit(Insn::new(ST_W, 10, 0, -4, 0));
    b.map_fd(mac);
    b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 2, 0, 0, -4));
    b.emit(Insn::new(CALL, 0, 0, 0, 1));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_DW, 1, 0, 0, 0));
    b.emit(Insn::new(STX_DW, 10, 1, -24, 0));
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        -16,
        i32::from_ne_bytes([0x6f, 0x6e, 0x6b, 0x01]),
    ));
    b.emit(Insn::new(STX_H, 10, 7, -12, 0));
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 14));
    b.emit(Insn::new(MOV_K, 3, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 43)); // bpf_skb_change_head
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 3, 0, 0, -24));
    b.emit(Insn::new(MOV_K, 4, 0, 0, 14));
    b.emit(Insn::new(MOV_K, 5, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 9)); // bpf_skb_store_bytes
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
}

pub struct AuxReturnLink {
    link: AuxTcxLink,
    program: OwnedFd,
    id: u32,
    pair: Arc<AuxDevicePair>,
    mac: Option<HostMac>,
}

impl AuxReturnLink {
    pub fn update_host_mac(
        &self,
        watch: &AuxLinkWatch,
        name: &str,
        info: &AuxLinkInfo,
    ) -> io::Result<()> {
        let result = (|| {
            let mac = self
                .mac
                .as_ref()
                .ok_or_else(|| invalid_data("not a Host Ethernet return"))?;
            if !info.is_l2 || info.mtu != mac.mtu {
                return Err(invalid_data("Host Ethernet return geometry changed"));
            }
            self.verify()?;
            verify_host_device(&self.pair, watch, name, info)?;
            mac.set(info.local_mac);
            self.pair.verify()
        })();
        if result.is_err() {
            self.pair.set_open(false)?;
        }
        result
    }

    pub fn verify(&self) -> io::Result<()> {
        self.link.verify(self.id)
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 2] {
        [self.link.as_fd(), self.program.as_fd()]
    }

    pub fn memory_bytes(&self) -> io::Result<usize> {
        let mac_bytes = self
            .mac
            .as_ref()
            .map(|mac| kernel_memory_bytes(mac.fd.as_fd()))
            .transpose()?
            .unwrap_or(0);
        self.link
            .memory_bytes()?
            .checked_add(kernel_memory_bytes(self.program.as_fd())?)
            .and_then(|n| n.checked_add(mac_bytes))
            .ok_or_else(|| invalid_data("TCX return reservation overflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::gateway::tests::{auxiliary_tun, require_vm};
    use super::*;

    #[test]
    fn host_fifo_reserves_for_both_queues_and_releases_with_its_owner() {
        let budget = MemoryBudget::new(1 << 20);
        let fifo = HostFifo::reserve(&budget).unwrap();
        assert_eq!(fifo.slots(), 2);
        assert!(budget.used() >= 2 * 3 * HOST_SKB_CHARGE_MAX as usize);
        assert!(HostFifo::reserve(&budget).is_err());
        drop(fifo);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_host_broadcast_swap_keeps_incumbent_through_invalid_snapshot() {
        require_vm();
        let (_outer, outer) = auxiliary_tun(None);
        let (_inner, inner) = auxiliary_tun(None);
        let budget = MemoryBudget::new(128 << 20);
        let pair = AuxDevicePair::new_host(outer, inner, &budget).unwrap();
        let root = pair.host_broadcasts_fd().unwrap();
        let address = Ipv4Addr::new(192, 0, 2, 255);
        pair.replace_host_broadcasts(&[address]).unwrap();
        let member = || lookup::<_, u32>(root, &0u32).unwrap();
        let populated = member().unwrap();
        pair.replace_host_broadcasts(&[address]).unwrap();
        assert_eq!(member(), Some(populated));
        pair.set_open(true).unwrap();
        assert_eq!(
            pair.replace_host_broadcasts(&[address, address])
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(member(), None);
        pair.verify_open().unwrap();
        pair.suspend_host_broadcasts().unwrap();
        pair.replace_host_broadcasts(&[address]).unwrap();
        assert!(member().is_some());
        pair.verify_open().unwrap();
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_aux_outer_anchor_cannot_activate_on_reused_ifindex() {
        require_vm();
        for direction in [TCX_INGRESS, TCX_EGRESS] {
            check_reused_ifindex(direction);
        }
    }

    fn check_reused_ifindex(direction: u32) {
        let (old_outer, outer) = auxiliary_tun(None);
        let (_inner, inner) = auxiliary_tun(None);
        let budget = MemoryBudget::new(128 << 20);
        let pair = AuxDevicePair::new(outer, inner, &budget).unwrap();
        let (classifier, classifier_id) =
            constant_program(TCX_DROP, b"honk_aux_test", direction).unwrap();

        let (owned, charge) = if direction == TCX_EGRESS {
            AuxTcxLink::host_egress(&pair, classifier.as_fd(), &budget)
        } else {
            AuxTcxLink::outer(&pair, classifier.as_fd(), &budget)
        }
        .unwrap();
        owned.verify(classifier_id).unwrap();
        let (replacement, id) = constant_program(TCX_NEXT, b"honk_aux_next", direction).unwrap();
        owned
            .replace(classifier.as_fd(), replacement.as_fd())
            .unwrap();
        assert!(
            owned
                .replace(classifier.as_fd(), replacement.as_fd())
                .is_err()
        );
        owned.verify(id).unwrap();
        if direction == TCX_INGRESS {
            owned.detach().unwrap();
        }
        drop((owned, charge));
        assert_eq!(Chain::read(outer, direction).unwrap().len, 0);
        pair.verify().unwrap();

        // Recreate the interleaving between outer()'s first slot check and link creation.
        drop(old_outer);
        let (_replacement, reused) = auxiliary_tun(Some(outer));
        let (neutral, neutral_id) =
            constant_program(TCX_NEXT, b"honk_aux_anchor", direction).unwrap();
        let chain = Chain::read(reused, direction).unwrap();
        let provisional = AuxTcxLink::attach(
            reused,
            direction,
            neutral.as_fd(),
            BPF_F_AFTER,
            0,
            chain.revision,
            None,
        )
        .unwrap();
        let error = provisional
            .activate_outer(&pair, neutral.as_fd(), classifier.as_fd())
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENODEV));
        provisional.verify(neutral_id).unwrap();
        provisional.detach().unwrap();
        assert_eq!(Chain::read(reused, direction).unwrap().len, 0);
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_host_return_header_uses_verified_mac_and_preserves_protocol() {
        use aya_obj::generated::{bpf_attr, bpf_cmd::BPF_PROG_TEST_RUN};

        require_vm();
        let target = HostMac::new(&AuxLinkInfo {
            ifindex: 1,
            mtu: 1500,
            up: true,
            is_l2: true,
            local_mac: [2; 6],
        })
        .unwrap();
        let mut b = Builder::new();
        b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
        ethernet_return_header(&mut b, target.fd.as_raw_fd());
        b.emit(Insn::new(LDX_W, 0, 9, 16, 0));
        b.jump(Insn::new(JNE_X, 0, 7, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        b.label(Label::Drop);
        b.emit(Insn::new(MOV_K, 0, 0, 0, TCX_DROP));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        let (program, _) = tcx_program(b, b"honk_test_hdr", TCX_INGRESS).unwrap();
        for (proto, mac) in [
            (0x0800u16, [2u8, 1, 2, 3, 4, 5]),
            (0x86dd, [4, 6, 7, 8, 9, 10]),
            (0x0806, [6; 6]),
        ] {
            target.set(mac);
            let mut input = [0u8; 60];
            input[12..14].copy_from_slice(&proto.to_be_bytes());
            let mut output = [0u8; 74];
            // SAFETY: both buffers live until the synchronous TEST_RUN returns.
            let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
            attr.test.prog_fd = program.as_raw_fd() as u32;
            attr.test.data_size_in = input.len() as u32;
            attr.test.data_in = input.as_ptr() as u64;
            attr.test.data_size_out = output.len() as u32;
            attr.test.data_out = output.as_mut_ptr() as u64;
            attr.test.repeat = 1;
            bpf(BPF_PROG_TEST_RUN as u32, &mut attr).unwrap();
            let test = unsafe { attr.test };
            if proto == 0x0806 {
                assert_eq!(test.retval, TCX_DROP as u32);
            } else {
                assert_eq!(test.retval, 0);
                assert_eq!(test.data_size_out, output.len() as u32);
                assert_eq!(&output[..6], &mac);
                assert_eq!(&output[6..12], &[0x02, 0x68, 0x6f, 0x6e, 0x6b, 0x01]);
                assert_eq!(&output[12..14], &proto.to_be_bytes());
                assert_eq!(&output[14..], &input);
            }
        }
    }

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_host_delay_filter_checks_full_timestamp_and_counts_before_the_ring() {
        use aya_obj::generated::{bpf_attr, bpf_cmd::BPF_PROG_TEST_RUN};

        require_vm();
        let (tun, index) = auxiliary_tun(None);
        let (_outer, outer) = auxiliary_tun(None);
        let budget = MemoryBudget::new(128 << 20);
        let mut guard = AuxTunGuard::install(index, tun.as_fd(), &budget).unwrap();
        let pair = AuxDevicePair::new(outer, index, &budget).unwrap();
        let maps = GatewayMaps::new_with_host(&[], &[], &[], &[1]).unwrap();
        let ct = HostConntrack::discover_accounted(&budget).unwrap();
        guard
            .install_host_delay_filter(tun.as_fd(), &pair, &maps, &budget, &ct)
            .unwrap();
        let filter = guard.delay_filter.as_ref().unwrap();
        let mut program = host_delay_filter(maps.stats_fd(), filter.admitted.as_fd(), &ct).unwrap();

        // Supply an exact clock only in this test-run program. Prepending the two
        // immediate words leaves all relative jumps in the emitted filter unchanged.
        const NOW: u64 = (37 << 32) + 17;
        let time = program
            .insns
            .iter_mut()
            .find(|i| i.code == CALL && i.imm == 5)
            .unwrap();
        *time = Insn::new(MOV_X, 0, 8, 0, 0);
        program.insns.splice(
            0..0,
            [
                Insn::new(LD_MAP, 8, 0, 0, NOW as i32),
                Insn::new(0, 0, 0, 0, (NOW >> 32) as i32),
            ],
        );
        program.len = program.insns.len();
        let (fd, _) = load_typed_program(&program, b"honk_test_age", &mut [0; 8192], 1, 0).unwrap();
        let mut count = 0;
        let mut drops = 0;
        for (time, valid, pass) in [
            (NOW, true, true),
            (NOW - (1 << 32), true, true),
            (NOW - HOST_PRIVATE_DELAY_NS, true, true),
            (NOW - HOST_PRIVATE_DELAY_NS - 1, true, false),
            (NOW + 1, true, false),
            (NOW, false, false),
            (0, true, false),
        ] {
            let mut frame = [0u8; 60];
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            let mut context = [0u32; 9];
            context[2] = time as u32;
            context[8] = (u32::from(valid) << 31) | (time >> 32) as u32;
            // SAFETY: all input buffers remain live for this synchronous TEST_RUN.
            let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
            attr.test.prog_fd = fd.as_raw_fd() as u32;
            attr.test.data_size_in = frame.len() as u32;
            attr.test.data_in = frame.as_ptr() as u64;
            attr.test.ctx_size_in = std::mem::size_of_val(&context) as u32;
            attr.test.ctx_in = context.as_ptr() as u64;
            attr.test.repeat = 1;
            bpf(BPF_PROG_TEST_RUN as u32, &mut attr).unwrap();
            // SOCKET_FILTER TEST_RUN presents the skb after eth_type_trans pulled the header.
            assert_eq!(unsafe { attr.test.retval }, if pass { 46 } else { 0 });
            count += u64::from(pass);
            drops += u64::from(!pass);
            assert_eq!(guard.admitted_records().unwrap(), count);
            assert_eq!(
                maps.reason_count(GatewayReason::HostLatePacket).unwrap(),
                drops
            );
            assert_eq!(
                maps.reason_count(GatewayReason::HostQueueCapacity).unwrap(),
                0
            );
        }
    }
}
