use super::attachment::{LinkUpdateAttr, pin_program, private_bpffs};
use super::*;
use honk_ebpf_common::host::{
    HOST_CAPTURE_HORIZON_NS, HOST_FACT_SLOTS, HOST_METADATA_LEN, HOST_METADATA_VERSION,
    HOST_PROCESS_PRESENT, HOST_REPRESENTATION_FLAGS, HOST_REPRESENTATION_MATERIALIZED,
    HOST_RETURN_LEN, HOST_SOURCE_FLAGS, HOST_SOURCE_LOCAL, HOST_STAGE_TCX_EGRESS, HostFactSlot,
    HostReturnDevice,
};

const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b;
const SUB_X: u8 = 0x1f;
const JGE_X: u8 = 0x3d;
const OR_X: u8 = 0x4f;
const TCX_INGRESS: u32 = 46;
const XDP_FRAGS_DEVICE_BOUND: u32 = (1 << 5) | (1 << 6);
const SNAPSHOT: i16 = -(HOST_METADATA_LEN as i16);

/// Private-XDP capture and the source-private terminal. The capture owner owns pins.
pub struct HostPrograms {
    programs: Programs,
    terminal: OwnedFd,
    terminal_id: u32,
    terminal_guard: OwnedFd,
    terminal_guard_id: u32,
    private_tx: u32,
}

impl HostPrograms {
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit cold-load authority and borrowed map descriptors"
    )]
    pub fn load(
        btf: &Btf,
        private_rx: u32,
        private_tx: u32,
        attachment: u64,
        source_netns: u64,
        tx_mac: [u8; 6],
        rx_mac: [u8; 6],
        facts: BorrowedFd<'_>,
        gate: BorrowedFd<'_>,
        returns: BorrowedFd<'_>,
    ) -> io::Result<Self> {
        validate_ifindex(private_rx)?;
        validate_ifindex(private_tx)?;
        if attachment == 0 || source_netns == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero Host authority",
            ));
        }
        map_layout(
            facts,
            2,
            size_of::<HostFactSlot>() as u32,
            Some(HOST_FACT_SLOTS as u32),
        )?;
        map_layout(gate, 2, 4, Some(1))?;
        map_layout(returns, 1, size_of::<HostReturnDevice>() as u32, Some(64))?;
        let mut kfuncs = [0; 2];
        for (id, name) in kfuncs
            .iter_mut()
            .zip(["bpf_xdp_metadata_rx_vlan_tag", "bpf_xdp_metadata_rx_hash"])
        {
            *id = btf
                .id_by_type_name_kind(name, BtfKind::Func)
                .map_err(|error| {
                    io::Error::new(io::ErrorKind::Unsupported, format!("Host {name}: {error}"))
                })?;
        }
        let counters = create_map(2, 8, 5, b"honk_host_count")?;
        let xsks = create_map(17, 4, 1, b"honk_host_xsks")?;
        let mut log = vec![0; 1 << 20];
        let mut guard = drop_program(XDP_DROP)?;
        guard.flags = XDP_FRAGS_DEVICE_BOUND;
        guard.ifindex = private_rx;
        let (discover, discover_id) = load_program(&guard, b"honk_host_guard", &mut log)?;
        let data_program = capture_program(
            private_rx,
            attachment,
            source_netns,
            tx_mac,
            rx_mac,
            facts.as_raw_fd(),
            gate.as_raw_fd(),
            returns.as_raw_fd(),
            xsks.as_raw_fd(),
            counters.as_raw_fd(),
            kfuncs,
        )?;
        let (data, data_id) = load_program(&data_program, b"honk_host_data", &mut log)?;
        let terminal_program =
            return_program(private_tx, attachment, tx_mac, rx_mac, returns.as_raw_fd())?;
        let (terminal, terminal_id) = load_typed_program(
            &terminal_program,
            b"honk_host_ret",
            &mut log,
            3,
            TCX_INGRESS,
        )?;
        let (terminal_guard, terminal_guard_id) = load_typed_program(
            &drop_program(2)?,
            b"honk_host_stop",
            &mut log,
            3,
            TCX_INGRESS,
        )?;
        Ok(Self {
            programs: Programs {
                counters,
                xsks,
                discover,
                data,
                discover_id,
                data_id,
                queues: 1,
                _gateway_fds: Vec::new(),
                gateway_config: None,
            },
            terminal,
            terminal_id,
            terminal_guard,
            terminal_guard_id,
            private_tx,
        })
    }

    pub fn programs(&self) -> &Programs {
        &self.programs
    }

    /// Read the kernel's cold memory charge before the capture owner pins or admits these FDs.
    pub fn memory_bytes(&self) -> io::Result<usize> {
        [
            self.programs.counters.as_raw_fd(),
            self.programs.xsks.as_raw_fd(),
            self.programs.discover.as_raw_fd(),
            self.programs.data.as_raw_fd(),
            self.terminal.as_raw_fd(),
            self.terminal_guard.as_raw_fd(),
        ]
        .into_iter()
        .try_fold(0usize, |total, fd| {
            // SAFETY: this descriptor remains owned by self throughout the readback.
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
            total
                .checked_add(kernel_memory_bytes(borrowed)?)
                .ok_or_else(|| invalid_data("Host kernel memory extent overflow"))
        })
    }

    /// Call in the source namespace after recording durable intent for this hook's pins.
    pub fn attach_return(&self, pin_root: &Path) -> io::Result<HostTcxAttachment> {
        HostTcxAttachment::create(
            self.private_tx,
            TCX_INGRESS,
            self.terminal.as_fd(),
            self.terminal_id,
            self.terminal_guard.as_fd(),
            self.terminal_guard_id,
            pin_root,
        )
    }

    pub fn guard_return(&self, link: &mut HostTcxAttachment) -> io::Result<()> {
        if link.ifindex != self.private_tx || link.attach_type != TCX_INGRESS {
            return Err(invalid_data("foreign Host return hook"));
        }
        link.guard(self.terminal.as_fd(), self.terminal_guard.as_fd())
    }
}

/// Pinned TCX custody survives Drop; only the joined capture owner removes its pins.
pub struct HostTcxAttachment {
    fd: OwnedFd,
    ifindex: u32,
    attach_type: u32,
    id: u32,
    program_id: u32,
    data_id: u32,
    guard_id: u32,
}

impl HostTcxAttachment {
    pub fn create(
        ifindex: u32,
        attach_type: u32,
        program: BorrowedFd<'_>,
        program_id: u32,
        guard: BorrowedFd<'_>,
        guard_id: u32,
        pin_root: &Path,
    ) -> io::Result<Self> {
        validate_ifindex(ifindex)?;
        if !matches!(attach_type, 46 | 47)
            || tc_program_id(program)? != program_id
            || tc_program_id(guard)? != guard_id
        {
            return Err(invalid_data("Host TCX program identity mismatch"));
        }
        let root = private_bpffs(pin_root)?;
        pin_program(root.as_fd(), c"program", program)?;
        pin_program(root.as_fd(), c"guard", guard)?;
        if !tcx_chain(ifindex, attach_type)?.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "foreign Host TCX hook",
            ));
        }
        #[repr(C)]
        struct Create {
            program: u32,
            target: u32,
            attach_type: u32,
            flags: u32,
            relative: u32,
            padding: u32,
            revision: u64,
        }
        let fd = bpf_fd(
            BPF_LINK_CREATE,
            &mut Create {
                program: program.as_raw_fd() as u32,
                target: ifindex,
                attach_type,
                flags: 1 << 4,
                relative: 0,
                padding: 0,
                revision: 0,
            },
        )?;
        if let Err(error) = pin_program(root.as_fd(), c"link", fd.as_fd()) {
            // Failed pinning cannot release a terminal into the source stack.
            std::mem::forget(fd);
            return Err(error);
        }
        let mut info = TcxInfo::default();
        object_info(fd.as_fd(), &mut info)?;
        let link = Self {
            fd,
            ifindex,
            attach_type,
            id: info.id,
            program_id,
            data_id: program_id,
            guard_id,
        };
        link.check()?;
        Ok(link)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn check(&self) -> io::Result<()> {
        let mut info = TcxInfo::default();
        object_info(self.fd.as_fd(), &mut info)?;
        if info.kind != 11
            || info.id == 0
            || info.id != self.id
            || info.program != self.program_id
            || info.ifindex != self.ifindex
            || info.attach_type != self.attach_type
            || tcx_chain(self.ifindex, self.attach_type)? != [self.program_id]
        {
            return Err(invalid_data("Host TCX custody changed"));
        }
        Ok(())
    }

    /// Close admission before the owner's real reader grace and pin cleanup.
    pub fn guard(&mut self, expected: BorrowedFd<'_>, guard: BorrowedFd<'_>) -> io::Result<()> {
        if tc_program_id(expected)? != self.data_id || tc_program_id(guard)? != self.guard_id {
            return Err(invalid_data("foreign Host TCX programs"));
        }
        self.check()?;
        if self.program_id == self.guard_id {
            return Ok(());
        }
        bpf(
            BPF_LINK_UPDATE,
            &mut LinkUpdateAttr {
                link_fd: self.fd.as_raw_fd() as u32,
                new_prog_fd: guard.as_raw_fd() as u32,
                flags: BPF_F_REPLACE,
                old_prog_fd: expected.as_raw_fd() as u32,
            },
        )?;
        self.program_id = self.guard_id;
        self.check()
    }
}

impl AsFd for HostTcxAttachment {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn tc_program_id(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut info = ProgInfo::default();
    object_info(fd, &mut info)?;
    if info.kind != 3 || info.id == 0 {
        return Err(invalid_data("Host program is not SCHED_CLS"));
    }
    Ok(info.id)
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

fn tcx_chain(ifindex: u32, attach_type: u32) -> io::Result<Vec<u32>> {
    #[repr(C)]
    struct Query {
        target: u32,
        attach_type: u32,
        query_flags: u32,
        attach_flags: u32,
        programs: u64,
        count: u32,
        padding: u32,
        program_flags: u64,
        links: u64,
        link_flags: u64,
        revision: u64,
    }
    let mut ids = [0u32; 2];
    let mut query = Query {
        target: ifindex,
        attach_type,
        query_flags: 0,
        attach_flags: 0,
        programs: ids.as_mut_ptr() as u64,
        count: ids.len() as u32,
        padding: 0,
        program_flags: 0,
        links: 0,
        link_flags: 0,
        revision: 0,
    };
    bpf(16, &mut query)?;
    if query.count as usize > ids.len() {
        return Err(invalid_data("Host return TCX chain exceeds admitted bound"));
    }
    Ok(ids[..query.count as usize].to_vec())
}

fn map_layout(
    fd: BorrowedFd<'_>,
    kind: u32,
    value_size: u32,
    entries: Option<u32>,
) -> io::Result<()> {
    #[repr(C)]
    #[derive(Default)]
    struct MapInfo {
        kind: u32,
        id: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        flags: u32,
    }
    let mut info = MapInfo::default();
    object_info(fd, &mut info)?;
    if info.kind != kind
        || info.id == 0
        || info.key_size != 4
        || info.value_size != value_size
        || info.max_entries == 0
        || entries.is_some_and(|entries| info.max_entries != entries)
    {
        return Err(invalid_data("Host typed map layout mismatch"));
    }
    Ok(())
}

fn drop_program(action: i32) -> io::Result<Program> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_K, 0, 0, 0, action));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn immediate64(b: &mut Builder, register: u8, value: u64) {
    b.emit(Insn::new(LD_MAP, register, 0, 0, value as u32 as i32));
    b.emit(Insn::new(0, 0, 0, 0, (value >> 32) as u32 as i32));
}

fn equal(b: &mut Builder, code: u8, base: u8, offset: i16, expected: i32) {
    b.emit(Insn::new(code, 0, base, offset, 0));
    b.jump(Insn::new(JNE32_K, 0, 0, 0, expected), Label::Drop);
}

fn bytes_equal(b: &mut Builder, offset: i16, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        equal(b, LDX_B, 6, offset + index as i16, i32::from(*byte));
    }
}

fn lookup(b: &mut Builder, fd: RawFd, key: i16) {
    b.map_fd(fd);
    b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
    b.emit(Insn::new(ADD_K, 2, 0, 0, i32::from(key)));
    b.emit(Insn::new(CALL, 0, 0, 0, 1));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
}

fn gate_open(b: &mut Builder, gate: RawFd) {
    b.emit(Insn::new(ST_W, 10, 0, -160, 0));
    lookup(b, gate, -160);
    equal(b, LDX_W, 0, 0, 1);
}

#[allow(
    clippy::too_many_arguments,
    reason = "emit the same explicit authority and descriptors validated by load"
)]
fn capture_program(
    private_rx: u32,
    attachment: u64,
    source_netns: u64,
    tx_mac: [u8; 6],
    rx_mac: [u8; 6],
    facts: RawFd,
    gate: RawFd,
    returns: RawFd,
    xsks: RawFd,
    counters: RawFd,
    kfuncs: [u32; 2],
) -> io::Result<Program> {
    let mut b = Builder::new();
    b.program.flags = XDP_FRAGS_DEVICE_BOUND;
    b.program.ifindex = private_rx;
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    equal(&mut b, LDX_W, 9, 12, private_rx as i32);
    equal(&mut b, LDX_W, 9, 16, 0);
    gate_open(&mut b, gate);
    b.emit(Insn::new(LDX_W, 6, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 4, 0));
    b.bound(14, Label::Drop);
    bytes_equal(&mut b, 0, &rx_mac);
    bytes_equal(&mut b, 6, &tx_mac);
    // Only untagged inner Ethernet is legal. Accelerated VLAN is read from the real driver.
    b.emit(Insn::new(LDX_H, 0, 6, 12, 0));
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, i32::from(0x0800u16.to_be())),
        Label::Ipv4,
    );
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, i32::from(0x86ddu16.to_be())),
        Label::Drop,
    );
    b.emit(Insn::new(ST_W, 10, 0, -156, 10));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Selected);
    b.label(Label::Ipv4);
    b.emit(Insn::new(ST_W, 10, 0, -156, 2));
    b.label(Label::Selected);
    for offset in [-144, -148, -152] {
        b.emit(Insn::new(ST_W, 10, 0, offset, 0));
    }
    for (kfunc, first, second) in [(kfuncs[0], -144, -142), (kfuncs[1], -148, -152)] {
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 2, 0, 0, first));
        b.emit(Insn::new(MOV_X, 3, 10, 0, 0));
        b.emit(Insn::new(ADD_K, 3, 0, 0, second));
        b.emit(Insn::new(CALL, 0, 2, 0, kfunc as i32));
        b.jump(Insn::new(JNE32_K, 0, 0, 0, 0), Label::Drop);
    }
    equal(&mut b, LDX_H, 10, -144, i32::from(0x8100u16.to_be()));
    equal(&mut b, LDX_W, 10, -152, 8); // XDP_RSS_TYPE_L4_ANY from the controlled hash.
    b.emit(Insn::new(LDX_H, 8, 10, -142, 0));
    b.emit(Insn::new(LSH_K, 8, 0, 0, 32));
    b.emit(Insn::new(LDX_W, 0, 10, -148, 0));
    b.emit(Insn::new(OR_X, 8, 0, 0, 0));
    b.jump(Insn::new(JEQ_K, 8, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 0, 8, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, -1));
    b.emit(Insn::new(AND_K, 0, 0, 0, (HOST_FACT_SLOTS - 1) as i32));
    b.emit(Insn::new(STX_W, 10, 0, -140, 0));
    lookup(&mut b, facts, -140);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    b.emit(Insn::new(MOV_X, 1, 6, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 93)); // Native bpf_spin_lock at map value offset zero.
    for offset in (0..HOST_METADATA_LEN as i16).step_by(8) {
        b.emit(Insn::new(LDX_DW, 0, 6, 8 + offset, 0));
        b.emit(Insn::new(STX_DW, 10, 0, SNAPSHOT + offset, 0));
    }
    b.emit(Insn::new(MOV_X, 1, 6, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 94)); // No branch/helper can leave the lock held.
    b.emit(Insn::new(LDX_DW, 0, 10, SNAPSHOT + 8, 0));
    b.jump(Insn::new(JNE_X, 0, 8, 0, 0), Label::Drop);
    b.emit(Insn::new(CALL, 0, 0, 0, 5)); // Sample MONOTONIC after the complete copy/unlock.
    b.emit(Insn::new(LDX_DW, 1, 10, SNAPSHOT + 16, 0));
    b.jump(Insn::new(JGT_X, 1, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_DW, 2, 10, SNAPSHOT + 24, 0));
    b.jump(Insn::new(JGE_X, 0, 2, 0, 0), Label::Drop);
    b.emit(Insn::new(SUB_X, 2, 1, 0, 0));
    b.jump(
        Insn::new(JNE_K, 2, 0, 0, HOST_CAPTURE_HORIZON_NS as i32),
        Label::Drop,
    );
    equal(&mut b, LDX_W, 10, SNAPSHOT, i32::from_ne_bytes(*b"HXH1"));
    equal(
        &mut b,
        LDX_H,
        10,
        SNAPSHOT + 4,
        i32::from(HOST_METADATA_VERSION),
    );
    equal(&mut b, LDX_H, 10, SNAPSHOT + 6, HOST_METADATA_LEN as i32);
    for (offset, expected) in [(32, source_netns), (40, attachment)] {
        b.emit(Insn::new(LDX_DW, 0, 10, SNAPSHOT + offset, 0));
        immediate64(&mut b, 1, expected);
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    }
    for offset in [48, 56, 104] {
        b.emit(Insn::new(LDX_DW, 0, 10, SNAPSHOT + offset, 0));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    }
    b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + 96, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, !(HOST_SOURCE_FLAGS as i32)));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + 96, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, HOST_SOURCE_LOCAL as i32));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + 96, 0));
    b.jump(
        Insn::new(JSET_K, 0, 0, 0, HOST_PROCESS_PRESENT as i32),
        Label::Ipv6,
    );
    equal(&mut b, LDX_W, 10, SNAPSHOT + 76, 0);
    for offset in [80, 88] {
        b.emit(Insn::new(LDX_DW, 0, 10, SNAPSHOT + offset, 0));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    }
    b.label(Label::Ipv6);
    equal(
        &mut b,
        LDX_H,
        10,
        SNAPSHOT + 100,
        i32::from(HOST_STAGE_TCX_EGRESS),
    );
    b.emit(Insn::new(LDX_H, 0, 10, SNAPSHOT + 102, 0));
    b.emit(Insn::new(LDX_W, 1, 10, -156, 0));
    // An AF_INET6 socket may emit mapped IPv4; the saved EtherType still owns wire extent.
    b.emit(Insn::new(JEQ_K, 0, 0, 2, 10));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 2), Label::Drop);
    b.jump(Insn::new(JNE_K, 1, 0, 0, 2), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + 112, 0));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 20), Label::Drop);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 20));
    b.emit(Insn::new(JNE_K, 1, 0, 1, 10));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 40));
    b.jump(Insn::new(0xad, 0, 2, 0, 0), Label::Drop); // JLT_X, full IPv6 header required.
    b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + 124, 0));
    b.emit(Insn::new(
        AND_K,
        0,
        0,
        0,
        !(HOST_REPRESENTATION_FLAGS as i32),
    ));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + 124, 0));
    b.emit(Insn::new(
        AND_K,
        0,
        0,
        0,
        HOST_REPRESENTATION_MATERIALIZED as i32,
    ));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + 64, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(STX_W, 10, 0, -140, 0));
    lookup(&mut b, returns, -140);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    b.emit(Insn::new(LDX_DW, 1, 6, 0, 0));
    b.emit(Insn::new(LDX_DW, 2, 10, SNAPSHOT + 56, 0));
    b.jump(Insn::new(JNE_X, 1, 2, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 1, 6, 8, 0));
    b.emit(Insn::new(LDX_W, 2, 10, -140, 0));
    b.jump(Insn::new(JNE_X, 1, 2, 0, 0), Label::Drop);
    equal(&mut b, LDX_W, 6, 12, 0);
    equal(&mut b, LDX_W, 6, 28, 0);
    gate_open(&mut b, gate);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, -(HOST_METADATA_LEN as i32)));
    b.emit(Insn::new(CALL, 0, 0, 0, 54));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::CountDrop);
    b.emit(Insn::new(LDX_W, 6, 9, 8, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 0, 0));
    b.bound(HOST_METADATA_LEN as i32, Label::Drop);
    for offset in (0..HOST_METADATA_LEN as i16).step_by(4) {
        b.emit(Insn::new(LDX_W, 0, 10, SNAPSHOT + offset, 0));
        b.emit(Insn::new(STX_W, 6, 0, offset, 0));
    }
    b.map_fd(xsks);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(MOV_K, 3, 0, 0, XDP_DROP));
    b.emit(Insn::new(CALL, 0, 0, 0, 51));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::CountDrop);
    b.emit(Insn::new(ST_W, 10, 0, -4, 4)); // Existing queues + 3 metadata-failure slot.
    b.count(counters);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn pull_header(b: &mut Builder, length: i32) {
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, length));
    b.emit(Insn::new(CALL, 0, 0, 0, 39));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 6, 9, 76, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 80, 0));
    b.bound(length, Label::Drop);
}

fn return_program(
    private_tx: u32,
    attachment: u64,
    tx_mac: [u8; 6],
    rx_mac: [u8; 6],
    returns: RawFd,
) -> io::Result<Program> {
    const L3: i32 = 14 + HOST_RETURN_LEN as i32;
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    for (offset, expected) in [
        (36, private_tx as i32),
        (40, private_tx as i32),
        (20, 0),
        (164, 0),
        (176, 0),
    ] {
        equal(&mut b, LDX_W, 9, offset, expected);
    }
    pull_header(&mut b, L3);
    bytes_equal(&mut b, 0, &tx_mac);
    bytes_equal(&mut b, 6, &rx_mac);
    bytes_equal(&mut b, 14, b"HRV1");
    equal(&mut b, LDX_H, 6, 18, 1);
    equal(&mut b, LDX_H, 6, 20, HOST_RETURN_LEN as i32);
    equal(&mut b, LDX_W, 6, 22, 1);
    bytes_equal(&mut b, 30, &attachment.to_ne_bytes());
    b.emit(Insn::new(LDX_W, 8, 6, 46, 0));
    b.jump(Insn::new(JEQ_K, 8, 0, 0, 0), Label::Drop);
    // Ifindices are namespace-relative: private_rx can numerically equal an original target.
    b.jump(Insn::new(JEQ_K, 8, 0, 0, private_tx as i32), Label::Drop);
    b.emit(Insn::new(STX_W, 10, 8, -4, 0));
    b.emit(Insn::new(LDX_W, 0, 6, 50, 0));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 20), Label::Drop);
    b.jump(
        Insn::new(JGT_K, 0, 0, 0, 65535 - HOST_RETURN_LEN as i32),
        Label::Drop,
    );
    b.emit(Insn::new(STX_W, 10, 0, -8, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, L3));
    b.emit(Insn::new(LDX_W, 1, 9, 0, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    // Copy the unaligned wire generation before the bounded header pull invalidates pointers.
    for offset in [0, 4] {
        b.emit(Insn::new(LDX_W, 0, 6, 38 + offset, 0));
        b.emit(Insn::new(STX_W, 10, 0, -16 + offset, 0));
    }
    b.emit(Insn::new(LDX_W, 0, 6, 26, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 4), Label::Ipv4);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 6), Label::Drop);
    bytes_equal(&mut b, 12, &0x86ddu16.to_be_bytes());
    pull_header(&mut b, L3 + 40);
    b.emit(Insn::new(LDX_B, 0, 6, L3 as i16, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x60), Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 6, (L3 + 4) as i16, 0));
    b.emit(Insn::new(BE16, 0, 0, 0, 16));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 40));
    b.emit(Insn::new(LDX_W, 1, 10, -8, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Selected);
    b.label(Label::Ipv4);
    bytes_equal(&mut b, 12, &0x0800u16.to_be_bytes());
    pull_header(&mut b, L3 + 20);
    b.emit(Insn::new(LDX_B, 0, 6, L3 as i16, 0));
    b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x40), Label::Drop);
    b.emit(Insn::new(AND_K, 1, 0, 0, 0x0f));
    b.jump(Insn::new(JLT_K, 1, 0, 0, 5), Label::Drop);
    b.emit(Insn::new(LSH_K, 1, 0, 0, 2));
    b.emit(Insn::new(LDX_W, 2, 10, -8, 0));
    b.jump(Insn::new(JGT_X, 1, 2, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 6, (L3 + 2) as i16, 0));
    b.emit(Insn::new(BE16, 0, 0, 0, 16));
    b.jump(Insn::new(JNE_X, 0, 2, 0, 0), Label::Drop);
    b.label(Label::Selected);
    lookup(&mut b, returns, -4);
    // Immutable source-owned map values are copied before any packet-changing helper.
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    for offset in (0..32).step_by(8) {
        b.emit(Insn::new(LDX_DW, 0, 6, offset, 0));
        b.emit(Insn::new(STX_DW, 10, 0, -48 + offset, 0));
    }
    b.emit(Insn::new(LDX_DW, 0, 10, -48, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_DW, 1, 10, -16, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, -40, 0));
    b.jump(Insn::new(JNE_X, 0, 8, 0, 0), Label::Drop);
    equal(&mut b, LDX_W, 10, -36, 0);
    equal(&mut b, LDX_W, 10, -20, 0);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, -(HOST_RETURN_LEN as i32)));
    b.emit(Insn::new(MOV_K, 3, 0, 0, 1));
    b.emit(Insn::new(MOV_K, 4, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 50));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 6, 9, 76, 0));
    b.emit(Insn::new(LDX_W, 7, 9, 80, 0));
    b.bound(14, Label::Drop);
    for (packet_offset, stack_offset) in [(0, -32), (6, -26)] {
        for byte in 0..6 {
            b.emit(Insn::new(LDX_B, 0, 10, stack_offset + byte, 0));
            b.emit(Insn::new(0x73, 6, 0, packet_offset + byte, 0)); // STX_B.
        }
    }
    b.emit(Insn::new(MOV_X, 1, 8, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 1)); // BPF_F_INGRESS restores ordinary Linux input.
    b.emit(Insn::new(CALL, 0, 0, 0, 23));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 7), Label::Drop);
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 2));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_memory_charge_requires_one_exact_decimal_memlock() {
        assert_eq!(
            fdinfo_memlock("pos:\t0\nmemlock:\t4096\nmap_id:\t7\n").unwrap(),
            4096
        );
        assert_eq!(fdinfo_memlock("memlock:\t0\n").unwrap(), 0);
        for invalid in [
            "map_mem_usage:\t4096\n",
            "memlock:\t4096\nmemlock:\t4096\n",
            "memlock:\n",
            "memlock:\t-1\n",
            "memlock:\t+1\n",
            "memlock:\t1 kB\n",
            "memlock:\t340282366920938463463374607431768211456\n",
        ] {
            assert_eq!(
                fdinfo_memlock(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
