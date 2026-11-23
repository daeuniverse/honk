//! TCX custody for explicitly configured layer-three gateway links.

use super::attachment::LinkUpdateAttr;
use super::gateway::{create_with_flags, lookup, update};
use super::*;
use aya_obj::generated::{BPF_F_AFTER, BPF_F_BEFORE, BPF_F_LINK, BPF_F_RDONLY_PROG};
use honk_netstack::{MemoryBudget, MemoryReservation};

pub(super) const OUTER_SLOT: i32 = 0;
pub(super) const INNER_SLOT: i32 = 1;
const TCX_INGRESS: u32 = 46;
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
    _memory: MemoryReservation,
}

impl AuxDevicePair {
    pub fn new(outer: u32, inner: u32, root: &Arc<MemoryBudget>) -> io::Result<Self> {
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
            inner,
            _memory: memory,
            namespace: namespace_identity()?,
        };
        pair.verify()?;
        Ok(pair)
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
    fn read(index: u32) -> io::Result<Self> {
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
            attach_type: TCX_INGRESS,
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

fn kernel_reservation(include_link: bool, include_chain: bool) -> io::Result<usize> {
    // TCX link fdinfo has no memlock. Reserve each live allocation separately, with room for
    // slab bookkeeping and the fdtable entry, rounded up to the running kernel's page size.
    let [link, entry, file] = ct::tcx_struct_sizes()?;
    // SAFETY: sysconf has no pointer arguments.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|p| p.is_power_of_two())
        .ok_or_else(|| invalid_data("invalid kernel page size"))?;
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
        let (neutral, _) = constant_program(TCX_NEXT, b"honk_aux_anchor")?;
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
        let chain = Chain::read(index)?;
        // An ifindex can be recycled between the pair lookup and BPF_LINK_CREATE.
        let link = Self::attach(
            index,
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
                attach_type: TCX_INGRESS,
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
            || info.attach_type != TCX_INGRESS
        {
            return Err(invalid_data("auxiliary TCX link identity changed"));
        }
        Ok(())
    }

    pub fn verify(&self, expected: u32) -> io::Result<()> {
        self.verify_fd(expected)?;
        let chain = Chain::read(self.index)?;
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

fn tcx_program(builder: Builder, name: &[u8]) -> io::Result<(OwnedFd, u32)> {
    load_typed_program(
        &builder.finish()?,
        name,
        &mut [0u8; 8192],
        SCHED_CLS,
        TCX_INGRESS,
    )
}

fn constant_program(verdict: i32, name: &[u8]) -> io::Result<(OwnedFd, u32)> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_K, 0, 0, 0, verdict));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    tcx_program(b, name)
}

/// A device-owned terminal on a newly created private TUN survives process exit until unregister.
pub struct AuxTunGuard {
    index: u32,
    program: OwnedFd,
    id: u32,
}

impl AuxTunGuard {
    pub fn install(inner: u32, tun: BorrowedFd<'_>, root: &Arc<MemoryBudget>) -> io::Result<Self> {
        validate_ifindex(inner)?;
        verify_private_tun(tun, inner)?;
        ct::tcx_struct_sizes_accounted(root)?;
        let chain = Chain::read(inner)?;
        if chain.len != 0 {
            return Err(invalid_data(
                "private auxiliary TUN has foreign TCX ingress",
            ));
        }
        // Only an FD-owned NEXT may be installed by ifindex alone. The durable operation names
        // this exact link after checking the TUN FD again, so ifindex reuse cannot inherit SHOT.
        let (neutral, neutral_id) = constant_program(TCX_NEXT, b"honk_aux_anchor")?;
        let stage_bytes = kernel_reservation(true, true)?
            .checked_add(kernel_memory_bytes(neutral.as_fd())?)
            .ok_or_else(|| invalid_data("auxiliary guard staging capacity overflow"))?;
        let _stage = root
            .reserve(stage_bytes)
            .ok_or_else(|| io::Error::other("auxiliary guard staging capacity"))?;
        let anchor =
            AuxTcxLink::attach(inner, neutral.as_fd(), BPF_F_AFTER, 0, chain.revision, None)?;
        verify_private_tun(tun, inner)?;
        let chain = Chain::read(inner)?;
        if !chain.entries().eq([(neutral_id, anchor.id)]) {
            return Err(invalid_data("private auxiliary TUN anchor changed"));
        }
        let (program, id) = constant_program(TCX_DROP, b"honk_aux_stop")?;
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
        };
        if !Chain::read(inner)?.entries().eq([(id, 0)]) {
            return Err(invalid_data("private auxiliary TUN guard install changed"));
        }
        Ok(guard)
    }

    pub fn verify(&self) -> io::Result<()> {
        let chain = Chain::read(self.index)?;
        if chain.entries().next_back() != Some((self.id, 0)) {
            return Err(invalid_data("private auxiliary TUN terminal changed"));
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
        pair.verify()?;
        if pair.inner != self.index || pair.namespace != namespace_identity()? {
            return Err(invalid_data("return link requires its owned device pair"));
        }
        pair.verify_gate(0)?;
        let chain = Chain::read(self.index)?;
        if !chain.entries().eq([(self.id, 0)]) {
            return Err(invalid_data("private TUN guard is not alone"));
        }
        let mut b = Builder::new();
        // __sk_buff.ifindex is UAPI offset 40; TC egress on the external device consumes the reply.
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
        b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
        b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
        b.emit(Insn::new(CALL, 0, 0, 0, 23)); // bpf_redirect(ifindex, 0)
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        b.label(Label::Drop);
        b.emit(Insn::new(MOV_K, 0, 0, 0, TCX_DROP));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        let (program, id) = tcx_program(b, b"honk_aux_return")?;
        let link = AuxTcxLink::attach(
            self.index,
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
            _pair: Arc::clone(pair),
        })
    }
}

pub struct AuxReturnLink {
    link: AuxTcxLink,
    program: OwnedFd,
    id: u32,
    _pair: Arc<AuxDevicePair>,
}

impl AuxReturnLink {
    pub fn verify(&self) -> io::Result<()> {
        self.link.verify(self.id)
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 2] {
        [self.link.as_fd(), self.program.as_fd()]
    }

    pub fn memory_bytes(&self) -> io::Result<usize> {
        self.link
            .memory_bytes()?
            .checked_add(kernel_memory_bytes(self.program.as_fd())?)
            .ok_or_else(|| invalid_data("TCX return reservation overflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::gateway::tests::{auxiliary_tun, require_vm};
    use super::*;

    #[test]
    #[ignore = "requires disposable VM root and private network namespace"]
    fn kernel_aux_outer_anchor_cannot_activate_on_reused_ifindex() {
        require_vm();
        let (old_outer, outer) = auxiliary_tun(None);
        let (_inner, inner) = auxiliary_tun(None);
        let budget = MemoryBudget::new(128 << 20);
        let pair = AuxDevicePair::new(outer, inner, &budget).unwrap();
        let (classifier, classifier_id) = constant_program(TCX_DROP, b"honk_aux_test").unwrap();

        let (owned, charge) = AuxTcxLink::outer(&pair, classifier.as_fd(), &budget).unwrap();
        owned.verify(classifier_id).unwrap();
        owned.detach().unwrap();
        drop((owned, charge));
        pair.verify().unwrap();

        // Recreate the interleaving between outer()'s first slot check and link creation.
        drop(old_outer);
        let (_replacement, reused) = auxiliary_tun(Some(outer));
        let (neutral, neutral_id) = constant_program(TCX_NEXT, b"honk_aux_anchor").unwrap();
        let chain = Chain::read(reused).unwrap();
        let provisional = AuxTcxLink::attach(
            reused,
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
        assert_eq!(Chain::read(reused).unwrap().len, 0);
    }
}
