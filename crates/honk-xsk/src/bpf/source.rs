//! Raw Host source programs; the concrete owner admits kernel layouts and hook custody.
use super::*;
use honk_ebpf_common::host::*;

const LDX_DW: u8 = 0x79;
const STX_DW: u8 = 0x7b;
const ST_H: u8 = 0x6a;
const STX_H: u8 = 0x6b;
const JGE_X: u8 = 0x3d;
const M: i16 = -128;
const E: i16 = -256;
const KEY: i16 = -260;
const DEVICE: i16 = -264;
const READY: i16 = -268;
const PROTOCOL: i16 = -272;
const TOKEN: i16 = -280;
const GATE_POINTER: i16 = -328;
const KSKB: i16 = -296;
const SCRATCH: i16 = -304;
const POINTER: i16 = -312;
const GOOD: i16 = -316;
const LOCK_POINTER: i16 = -336;
const BANK_VERSION: i16 = -344;

/// Offsets are admitted by the owner's existing kernel BTF reader, not guessed here.
/// `sock_wfree` is the actual running-kernel function address, not its BTF type ID.
#[derive(Clone, Copy, Debug)]
pub struct HostSourceConfig {
    pub source_netns: u64,
    pub attachment: u64,
    pub private_tx: u32,
    pub bypass_mark: u32,
    pub tx_mac: [u8; 6],
    pub rx_mac: [u8; 6],
    pub skb_sk_offset: u32,
    pub sock_net_pointer_offset: u32,
    pub net_cookie_offset: u32,
    pub skb_destructor_offset: u32,
    pub skb_truesize_offset: u32,
    pub sock_wmem_offset: u32,
    pub sock_refcnt_offset: u32,
    pub sock_write_queue_len_offset: u32,
    pub sock_wfree: u64,
}

pub struct HostSourcePrograms {
    source: OwnedFd,
    source_id: u32,
    guard: OwnedFd,
    guard_id: u32,
    selector: OwnedFd,
    selector_id: u32,
}

impl HostSourcePrograms {
    pub fn load(
        config: &HostSourceConfig,
        btf: &Btf,
        facts: BorrowedFd<'_>,
        gate: BorrowedFd<'_>,
        sequence: BorrowedFd<'_>,
        (sockets, socket_locks): (BorrowedFd<'_>, BorrowedFd<'_>),
        returns: BorrowedFd<'_>,
    ) -> io::Result<Self> {
        validate_ifindex(config.private_tx)?;
        if !cfg!(target_arch = "x86_64")
            || config.source_netns == 0
            || config.attachment == 0
            || config.bypass_mark == 0
            || config.sock_wfree == 0
            || config.bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
            || [
                config.skb_sk_offset,
                config.sock_net_pointer_offset,
                config.net_cookie_offset,
                config.skb_destructor_offset,
                config.skb_truesize_offset,
                config.sock_wmem_offset,
                config.sock_refcnt_offset,
                config.sock_write_queue_len_offset,
            ]
            .iter()
            .any(|&offset| offset > i32::MAX as u32 - 8)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unadmitted Host source layout/authority",
            ));
        }
        for (fd, kind, size, count, flags) in [
            (facts, 2, 136, HOST_FACT_SLOTS as u32, 0),
            (gate, 2, 4, 1, 0),
            (sequence, 2, 16, 1, 0),
            (sockets, 2, 520, HOST_SOCKET_BUCKETS as u32, 1024),
            (socket_locks, 2, 8, HOST_SOCKET_BUCKETS as u32, 0),
            (returns, 1, 32, 64, 0),
        ] {
            map_shape(fd, kind, size, count, flags)?;
        }
        let cast = btf
            .id_by_type_name_kind("bpf_cast_to_kern_ctx", BtfKind::Func)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("Host kernel-context cast: {error}"),
                )
            })?;
        let maps = Maps {
            facts: facts.as_raw_fd(),
            gate: gate.as_raw_fd(),
            sequence: sequence.as_raw_fd(),
            sockets: sockets.as_raw_fd(),
            socket_locks: socket_locks.as_raw_fd(),
            returns: returns.as_raw_fd(),
        };
        let mut log = vec![0; 1 << 20];
        let (source, source_id) = load_typed_program(
            &producer(config, maps, cast, false)?,
            b"honk_host_src",
            &mut log,
            3,
            47,
        )?;
        let (selector, selector_id) = load_typed_program(
            &selector(config, maps, cast)?,
            b"honk_host_sel",
            &mut log,
            8,
            1,
        )?;
        let (guard, guard_id) = load_typed_program(
            &producer(config, maps, cast, true)?,
            b"honk_host_stop",
            &mut log,
            3,
            47,
        )?;
        Ok(Self {
            source,
            source_id,
            guard,
            guard_id,
            selector,
            selector_id,
        })
    }

    pub fn source(&self) -> (BorrowedFd<'_>, u32) {
        (self.source.as_fd(), self.source_id)
    }
    pub fn guard(&self) -> (BorrowedFd<'_>, u32) {
        (self.guard.as_fd(), self.guard_id)
    }
    pub fn selector(&self) -> (BorrowedFd<'_>, u32) {
        (self.selector.as_fd(), self.selector_id)
    }
}

#[derive(Clone, Copy)]
struct Maps {
    facts: RawFd,
    gate: RawFd,
    sequence: RawFd,
    sockets: RawFd,
    socket_locks: RawFd,
    returns: RawFd,
}

fn map_shape(fd: BorrowedFd<'_>, kind: u32, size: u32, count: u32, flags: u32) -> io::Result<()> {
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        kind: u32,
        id: u32,
        key: u32,
        value: u32,
        count: u32,
        flags: u32,
    }
    let mut info = Info::default();
    object_info(fd, &mut info)?;
    if info.kind != kind
        || info.id == 0
        || info.key != 4
        || info.value != size
        || info.count != count
        || info.flags != flags
    {
        return Err(invalid_data("Host source map ABI mismatch"));
    }
    Ok(())
}

fn imm(b: &mut Builder, dst: u8, value: u64) {
    b.emit(Insn::new(LD_MAP, dst, 0, 0, value as i32));
    b.emit(Insn::new(0, 0, 0, 0, (value >> 32) as i32));
}
fn ahead(b: &mut Builder, code: u8, dst: u8, src: u8, value: i32) -> usize {
    b.emit(Insn::new(code, dst, src, 0, value))
}
fn patch(b: &mut Builder, at: usize) {
    b.program.insns[at].off = (b.program.len - at - 1) as i16;
}
fn stack(b: &mut Builder, dst: u8, offset: i16) {
    b.emit(Insn::new(MOV_X, dst, 10, 0, 0));
    b.emit(Insn::new(ADD_K, dst, 0, 0, offset as i32));
}
fn lookup(b: &mut Builder, fd: RawFd, key: i16) {
    b.map_fd(fd);
    stack(b, 2, key);
    b.emit(Insn::new(CALL, 0, 0, 0, 1));
}
fn lock(b: &mut Builder, reg: u8, acquire: bool) {
    b.emit(Insn::new(MOV_X, 1, reg, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, if acquire { 93 } else { 94 }));
}
fn require(b: &mut Builder, code: u8, reg: u8, offset: i16, value: i32) {
    b.emit(Insn::new(code, 0, reg, offset, 0));
    b.jump(Insn::new(JNE32_K, 0, 0, 0, value), Label::Drop);
}
fn gate(b: &mut Builder, fd: RawFd) {
    b.emit(Insn::new(ST_W, 10, 0, KEY, 0));
    lookup(b, fd, KEY);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(STX_DW, 10, 0, GATE_POINTER, 0));
    b.emit(Insn::new(LDX_W, 0, 0, 0, 0));
    b.emit(Insn::new(STX_W, 10, 0, READY, 0));
}
fn read_kernel(b: &mut Builder, base: u8, offset: u32, size: i32, dest: i16, failure: Label) {
    b.emit(Insn::new(MOV_X, 3, base, 0, 0));
    b.emit(Insn::new(ADD_K, 3, 0, 0, offset as i32));
    stack(b, 1, dest);
    b.emit(Insn::new(MOV_K, 2, 0, 0, size));
    b.emit(Insn::new(CALL, 0, 0, 0, 113));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), failure);
}

/// Keep ctx in r9, scalar actual socket in r8, nonzero cookie in r7.
fn origin(b: &mut Builder, c: &HostSourceConfig, cast: u32, selector: bool) {
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    for off in (M..0).step_by(8) {
        b.emit(Insn::new(0x7a, 10, 0, off, 0));
    }
    b.emit(Insn::new(LDX_W, 0, 9, 36, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Pass);
    b.emit(Insn::new(LDX_DW, 1, 9, 168, 0));
    // Cold admission excludes pre-TCX transforms that could orphan an already-Host packet.
    b.jump(Insn::new(JEQ_K, 1, 0, 0, 0), Label::Pass);
    b.emit(Insn::new(CALL, 0, 0, 0, 95));
    // Request/timewait sockets are existing kernel operations, never Host fullsocket owners.
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Pass);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    b.emit(Insn::new(LDX_W, 0, 6, 4, 0));
    let v4 = ahead(b, JEQ_K, 0, 0, 2);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 10), Label::Pass);
    patch(b, v4);
    b.emit(Insn::new(STX_H, 10, 0, M + 102, 0));
    b.emit(Insn::new(LDX_W, 0, 6, 12, 0));
    b.emit(Insn::new(STX_W, 10, 0, PROTOCOL, 0));
    let udp = ahead(b, JEQ_K, 0, 0, 17);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 6), Label::Pass);
    b.emit(Insn::new(LDX_W, 0, 6, 8, 0));
    b.jump(Insn::new(JNE32_K, 0, 0, 0, 1), Label::Pass);
    let typed = ahead(b, JA, 0, 0, 0);
    patch(b, udp);
    b.emit(Insn::new(LDX_W, 0, 6, 8, 0));
    b.jump(Insn::new(JNE32_K, 0, 0, 0, 2), Label::Pass);
    patch(b, typed);
    // An IPv6 dual-stack socket may emit IPv4; the copied socket AF stays unchanged.
    b.emit(Insn::new(LDX_W, 0, 9, 16, 0));
    let wire_v4 = ahead(b, JEQ_K, 0, 0, 0x0800u16.to_be() as i32);
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, 0x86ddu16.to_be() as i32),
        Label::Drop,
    );
    require(b, LDX_H, 10, M + 102, 10);
    patch(b, wire_v4);
    b.emit(Insn::new(LDX_W, 0, 6, 16, 0));
    b.emit(Insn::new(STX_W, 10, 0, M + 72, 0));
    // Scalarize the fullsocket pointer by a checked kernel read, not pointer ALU.
    b.emit(Insn::new(STX_DW, 10, 6, POINTER, 0));
    stack(b, 3, POINTER);
    stack(b, 1, SCRATCH);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 8));
    b.emit(Insn::new(CALL, 0, 0, 0, 113));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_DW, 8, 10, SCRATCH, 0));
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(CALL, 0, 2, 0, cast as i32));
    b.emit(Insn::new(STX_DW, 10, 0, KSKB, 0));
    read_kernel(b, 0, c.skb_sk_offset, 8, SCRATCH, Label::Drop);
    b.emit(Insn::new(LDX_DW, 0, 10, SCRATCH, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JNE_X, 0, 8, 0, 0), Label::Drop);
    read_kernel(b, 8, c.sock_net_pointer_offset, 8, SCRATCH, Label::Drop);
    b.emit(Insn::new(LDX_DW, 0, 10, SCRATCH, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    read_kernel(b, 0, c.net_cookie_offset, 8, M + 32, Label::Drop);
    b.emit(Insn::new(LDX_DW, 0, 10, M + 32, 0));
    imm(b, 1, c.source_netns);
    b.jump(
        Insn::new(JNE_X, 0, 1, 0, 0),
        if selector { Label::Pass } else { Label::Drop },
    );
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 46));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 7, 0, 0, 0));
    b.emit(Insn::new(STX_DW, 10, 7, M + 48, 0));
    b.emit(Insn::new(LDX_W, 0, 9, 40, 0));
    b.emit(Insn::new(STX_W, 10, 0, M + 64, 0));
    b.emit(Insn::new(LDX_W, 0, 9, 8, 0));
    b.emit(Insn::new(STX_W, 10, 0, M + 68, 0));
}

/// Caller holds the external bucket lock. r6 = payload; r5 = match, r4 = first empty.
fn find_entry(b: &mut Builder) {
    b.emit(Insn::new(MOV_K, 5, 0, 0, 0));
    b.emit(Insn::new(MOV_K, 4, 0, 0, 0));
    for way in 0..HOST_SOCKET_WAYS as i16 {
        let off = 8 + way * 64;
        b.emit(Insn::new(LDX_DW, 0, 6, off, 0));
        let other = ahead(b, JNE_X, 0, 7, 0);
        b.emit(Insn::new(LDX_DW, 1, 6, off + 8, 0));
        let address = ahead(b, JNE_X, 1, 8, 0);
        b.emit(Insn::new(MOV_X, 5, 6, 0, 0));
        b.emit(Insn::new(ADD_K, 5, 0, 0, off as i32));
        patch(b, other);
        patch(b, address);
        let used = ahead(b, JNE_K, 0, 0, 0);
        let have = ahead(b, JNE_K, 4, 0, 0);
        b.emit(Insn::new(MOV_X, 4, 6, 0, 0));
        b.emit(Insn::new(ADD_K, 4, 0, 0, off as i32));
        patch(b, used);
        patch(b, have);
    }
}
fn bank(b: &mut Builder, fd: RawFd, locks: RawFd) {
    b.emit(Insn::new(MOV_X, 0, 7, 0, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, (HOST_SOCKET_BUCKETS - 1) as i32));
    b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
    lookup(b, fd, KEY);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    lookup(b, locks, KEY);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(STX_DW, 10, 0, LOCK_POINTER, 0));
}
fn bank_lock(b: &mut Builder, acquire: bool) {
    b.emit(Insn::new(LDX_DW, 1, 10, LOCK_POINTER, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, if acquire { 93 } else { 94 }));
}

/// Raw instruction order is the compiler barrier. Admitted x86-64 stores preserve
/// odd-before-payload and payload-before-even; versions never wrap or reset.
fn begin_write(b: &mut Builder, failure: Label) {
    b.emit(Insn::new(LDX_DW, 0, 6, 0, 0));
    let odd = ahead(b, 0x45, 0, 0, 1);
    imm(b, 1, u64::MAX - 1);
    let exhausted = ahead(b, JGE_X, 0, 1, 0);
    b.emit(Insn::new(ADD_K, 0, 0, 0, 1));
    b.emit(Insn::new(STX_DW, 6, 0, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 1));
    b.emit(Insn::new(STX_DW, 10, 0, BANK_VERSION, 0));
    let ready = ahead(b, JA, 0, 0, 0);
    patch(b, odd);
    patch(b, exhausted);
    bank_lock(b, false);
    b.emit(Insn::new(LDX_DW, 1, 10, GATE_POINTER, 0));
    b.emit(Insn::new(ST_W, 1, 0, 0, 0));
    b.jump(Insn::new(JA, 0, 0, 0, 0), failure);
    patch(b, ready);
}

fn end_write(b: &mut Builder) {
    b.emit(Insn::new(LDX_DW, 0, 10, BANK_VERSION, 0));
    b.emit(Insn::new(STX_DW, 6, 0, 0, 0));
}
fn snapshot(b: &mut Builder) {
    for off in (E..E + 64).step_by(8) {
        b.emit(Insn::new(0x7a, 10, 0, off, 0));
    }
    bank_lock(b, true);
    find_entry(b);
    let absent = ahead(b, JEQ_K, 5, 0, 0);
    for off in (0..64).step_by(8) {
        b.emit(Insn::new(LDX_DW, 0, 5, off, 0));
        b.emit(Insn::new(STX_DW, 10, 0, E + off, 0));
    }
    patch(b, absent);
    bank_lock(b, false);
}
fn reserve(b: &mut Builder, fd: RawFd) {
    b.emit(Insn::new(ST_W, 10, 0, KEY, 0));
    lookup(b, fd, KEY);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    imm(b, 7, HOST_ID_MAX);
    lock(b, 6, true);
    b.emit(Insn::new(LDX_DW, 8, 6, 8, 0));
    let zero = ahead(b, JEQ_K, 8, 0, 0);
    let exhausted = ahead(b, JGT_X, 8, 7, 0);
    b.emit(Insn::new(MOV_X, 0, 8, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 1));
    b.emit(Insn::new(STX_DW, 6, 0, 8, 0));
    let done = ahead(b, JA, 0, 0, 0);
    patch(b, zero);
    patch(b, exhausted);
    b.emit(Insn::new(MOV_K, 8, 0, 0, 0));
    patch(b, done);
    lock(b, 6, false);
    b.jump(Insn::new(JEQ_K, 8, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(STX_DW, 10, 8, TOKEN, 0));
}
fn end(b: &mut Builder, selector: bool) {
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, if selector { 0 } else { 2 }));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Pass);
    b.emit(Insn::new(MOV_K, 0, 0, 0, if selector { 1 } else { -1 }));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
}

fn producer(c: &HostSourceConfig, maps: Maps, cast: u32, closed: bool) -> io::Result<Program> {
    let mut b = Builder::new();
    origin(&mut b, c, cast, false);
    bank(&mut b, maps.sockets, maps.socket_locks);
    snapshot(&mut b);
    b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_KERNEL as i32),
        Label::Pass,
    );
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_UNSELECTED as i32),
        Label::Pass,
    );
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_TRANSITION as i32),
        Label::Drop,
    );
    let endpoint = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
    b.emit(Insn::new(LDX_W, 0, 10, M + 72, 0));
    b.jump(Insn::new(0x16, 0, 0, 0, c.bypass_mark as i32), Label::Pass);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
    patch(&mut b, endpoint);
    if closed {
        // Physical sources keep ordinary kernel/neighbor traffic; only captured custody closes.
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
        end(&mut b, false);
        return b.finish();
    }
    gate(&mut b, maps.gate);
    require(&mut b, LDX_W, 10, READY, 1);
    b.emit(Insn::new(LDX_W, 0, 10, M + 64, 0));
    b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
    lookup(&mut b, maps.returns, KEY);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    require(&mut b, LDX_W, 6, 12, 0);
    require(&mut b, LDX_W, 6, 28, 0);
    b.emit(Insn::new(LDX_W, 0, 6, 8, 0));
    b.emit(Insn::new(LDX_W, 1, 10, KEY, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_DW, 0, 6, 0, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(STX_DW, 10, 0, M + 56, 0));
    b.emit(Insn::new(LDX_DW, 0, 10, E + 40, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(STX_DW, 10, 0, M + 104, 0));
    b.emit(Insn::new(ST_W, 10, 0, M + 96, HOST_SOURCE_LOCAL as i32));
    b.emit(Insn::new(LDX_W, 0, 10, E + 36, 0));
    b.emit(Insn::new(
        AND_K,
        0,
        0,
        0,
        HOST_SOCKET_PROCESS_PRESENT as i32,
    ));
    let unknown = ahead(&mut b, JEQ_K, 0, 0, 0);
    for off in (0..20).step_by(4) {
        b.emit(Insn::new(LDX_W, 0, 10, E + 16 + off, 0));
        b.emit(Insn::new(STX_W, 10, 0, M + 76 + off, 0));
    }
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        M + 96,
        (HOST_SOURCE_LOCAL | HOST_PROCESS_PRESENT) as i32,
    ));
    patch(&mut b, unknown);
    imm(&mut b, 0, c.attachment);
    b.emit(Insn::new(STX_DW, 10, 0, M + 40, 0));
    b.emit(Insn::new(ST_W, 10, 0, M, i32::from_ne_bytes(*b"HXH1")));
    b.emit(Insn::new(ST_H, 10, 0, M + 4, HOST_METADATA_VERSION as i32));
    b.emit(Insn::new(ST_H, 10, 0, M + 6, HOST_METADATA_LEN as i32));
    b.emit(Insn::new(
        ST_H,
        10,
        0,
        M + 100,
        HOST_STAGE_TCX_EGRESS as i32,
    ));
    require(&mut b, LDX_W, 9, 20, 0); // No inherited accelerated tag in the admitted plain prefix.
    b.emit(Insn::new(LDX_W, 0, 9, 0, 0));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 34), Label::Drop);
    b.jump(Insn::new(JGT_K, 0, 0, 0, 65535 + 14), Label::Drop);
    b.emit(Insn::new(ADD_K, 0, 0, 0, -14));
    b.emit(Insn::new(STX_W, 10, 0, M + 112, 0));
    for (ctx, to) in [(176, 116), (164, 120)] {
        b.emit(Insn::new(LDX_W, 0, 9, ctx, 0));
        b.emit(Insn::new(STX_W, 10, 0, M + to, 0));
    }
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        M + 124,
        HOST_REPRESENTATION_MATERIALIZED as i32,
    ));
    b.emit(Insn::new(LDX_W, 0, 10, M + 116, 0));
    let ordinary = ahead(&mut b, JEQ_K, 0, 0, 0);
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        M + 124,
        (HOST_REPRESENTATION_MATERIALIZED | HOST_REPRESENTATION_GSO) as i32,
    ));
    patch(&mut b, ordinary);
    // A bounded read validates Ethernet without pulling/linearizing the original L3 payload.
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 12));
    stack(&mut b, 3, SCRATCH);
    b.emit(Insn::new(MOV_K, 4, 0, 0, 2));
    b.emit(Insn::new(CALL, 0, 0, 0, 26));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 10, SCRATCH, 0));
    b.emit(Insn::new(LDX_W, 1, 9, 16, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    let wire_v4 = ahead(&mut b, JEQ_K, 0, 0, 0x0800u16.to_be() as i32);
    b.emit(Insn::new(LDX_W, 0, 10, M + 112, 0));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 40), Label::Drop);
    patch(&mut b, wire_v4);
    b.emit(Insn::new(CALL, 0, 0, 0, 5));
    b.emit(Insn::new(STX_DW, 10, 0, M + 16, 0));
    b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
    b.emit(Insn::new(ADD_K, 1, 0, 0, HOST_CAPTURE_HORIZON_NS as i32));
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(STX_DW, 10, 1, M + 24, 0));
    reserve(&mut b, maps.sequence);
    b.emit(Insn::new(STX_DW, 10, 8, M + 8, 0));
    b.emit(Insn::new(MOV_X, 0, 8, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, -1));
    b.emit(Insn::new(AND_K, 0, 0, 0, (HOST_FACT_SLOTS - 1) as i32));
    b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
    lookup(&mut b, maps.facts, KEY);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    b.emit(Insn::new(MOV_K, 7, 0, 0, 0));
    lock(&mut b, 6, true);
    b.emit(Insn::new(LDX_DW, 0, 6, 16, 0));
    let newer = ahead(&mut b, JGE_X, 0, 8, 0);
    b.emit(Insn::new(LDX_DW, 0, 6, 32, 0));
    b.emit(Insn::new(LDX_DW, 1, 10, M + 16, 0));
    let live = ahead(&mut b, JGT_X, 0, 1, 0);
    for off in (0..128).step_by(8) {
        b.emit(Insn::new(LDX_DW, 0, 10, M + off, 0));
        b.emit(Insn::new(STX_DW, 6, 0, 8 + off, 0));
    }
    b.emit(Insn::new(MOV_K, 7, 0, 0, 1));
    patch(&mut b, newer);
    patch(&mut b, live);
    lock(&mut b, 6, false);
    b.jump(Insn::new(JEQ_K, 7, 0, 0, 0), Label::Drop);
    gate(&mut b, maps.gate);
    require(&mut b, LDX_W, 10, READY, 1);
    b.emit(Insn::new(CALL, 0, 0, 0, 5));
    b.emit(Insn::new(LDX_DW, 1, 10, M + 24, 0));
    b.jump(Insn::new(JGE_X, 0, 1, 0, 0), Label::Drop);
    let mut ethernet = [0u8; 12];
    ethernet[..6].copy_from_slice(&c.rx_mac);
    ethernet[6..].copy_from_slice(&c.tx_mac);
    for (word, bytes) in ethernet.as_chunks::<4>().0.iter().enumerate() {
        b.emit(Insn::new(
            ST_W,
            10,
            0,
            E + word as i16 * 4,
            i32::from_ne_bytes(*bytes),
        ));
    }
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    stack(&mut b, 3, E);
    b.emit(Insn::new(MOV_K, 4, 0, 0, 12));
    b.emit(Insn::new(MOV_K, 5, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 9));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(LDX_W, 2, 10, M + 8, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 48));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0x8100u16.to_be() as i32));
    b.emit(Insn::new(LDX_H, 3, 10, M + 12, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 18));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_K, 1, 0, 0, c.private_tx as i32));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 23));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 7), Label::Drop);
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    end(&mut b, false);
    b.finish()
}

/// Match the stack's eight-header bound without pulling or copying the packet body.
fn first_syn(b: &mut Builder) {
    const HEADER: i16 = -384;
    const OFFSET: i16 = -388;
    const END: i16 = -392;
    const NEXT: i16 = -396;
    const EXT: i16 = -400;
    packet_load(b, Some(0), HEADER, 20);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    packet_word(b, 0, 16);
    let ipv6 = ahead(b, JNE_K, 0, 0, 0x0800u16.to_be() as i32);
    require(b, LDX_B, 10, HEADER + 9, 6);
    b.emit(Insn::new(LDX_B, 0, 10, HEADER, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x40), Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 10, HEADER + 6, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0x3fffu16.to_be() as i32));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 10, HEADER, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 15));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 5), Label::Drop);
    b.emit(Insn::new(LSH_K, 0, 0, 0, 2));
    b.emit(Insn::new(STX_W, 10, 0, OFFSET, 0));
    b.emit(Insn::new(LDX_H, 0, 10, HEADER + 2, 0));
    b.emit(Insn::new(BE16, 0, 0, 0, 16));
    b.emit(Insn::new(STX_W, 10, 0, END, 0));
    let ipv4_tcp = ahead(b, JA, 0, 0, 0);
    patch(b, ipv6);
    b.emit(Insn::new(LDX_B, 0, 10, HEADER, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x60), Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 10, HEADER + 4, 0));
    b.emit(Insn::new(BE16, 0, 0, 0, 16));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 40));
    b.emit(Insn::new(STX_W, 10, 0, END, 0));
    packet_word(b, 1, 0);
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(ST_W, 10, 0, OFFSET, 40));
    b.emit(Insn::new(LDX_B, 0, 10, HEADER + 6, 0));
    b.emit(Insn::new(STX_W, 10, 0, NEXT, 0));
    let mut tcp = [0; 8];
    for found in &mut tcp {
        b.emit(Insn::new(LDX_W, 0, 10, NEXT, 0));
        *found = ahead(b, JEQ_K, 0, 0, 6);
        let hop = ahead(b, JEQ_K, 0, 0, 0);
        let routing = ahead(b, JEQ_K, 0, 0, 43);
        let destination = ahead(b, JEQ_K, 0, 0, 60);
        // Match Endpoint: AH/ESP, fragments, No Next Header and unknown protocols refuse.
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
        patch(b, hop);
        patch(b, routing);
        patch(b, destination);
        b.emit(Insn::new(LDX_W, 2, 10, OFFSET, 0));
        b.emit(Insn::new(MOV_X, 0, 2, 0, 0));
        b.emit(Insn::new(ADD_K, 0, 0, 0, 4));
        b.emit(Insn::new(LDX_W, 1, 10, END, 0));
        b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
        packet_load(b, None, EXT, 4);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_W, 0, 10, NEXT, 0));
        let not_routing = ahead(b, JNE_K, 0, 0, 43);
        require(b, LDX_B, 10, EXT + 3, 0);
        patch(b, not_routing);
        b.emit(Insn::new(LDX_B, 1, 10, EXT + 1, 0));
        b.emit(Insn::new(ADD_K, 1, 0, 0, 1));
        b.emit(Insn::new(LSH_K, 1, 0, 0, 3));
        b.emit(Insn::new(LDX_W, 0, 10, OFFSET, 0));
        b.emit(Insn::new(ADD_X, 0, 1, 0, 0));
        b.emit(Insn::new(LDX_W, 1, 10, END, 0));
        b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
        b.emit(Insn::new(STX_W, 10, 0, OFFSET, 0));
        b.emit(Insn::new(LDX_B, 0, 10, EXT, 0));
        b.emit(Insn::new(STX_W, 10, 0, NEXT, 0));
    }
    require(b, LDX_W, 10, NEXT, 6);
    for found in tcp {
        patch(b, found);
    }
    patch(b, ipv4_tcp);
    b.emit(Insn::new(LDX_W, 0, 10, END, 0));
    packet_word(b, 1, 0);
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
    b.jump(Insn::new(JGT_K, 0, 0, 0, 65535), Label::Drop);
    b.emit(Insn::new(LDX_W, 2, 10, OFFSET, 0));
    b.emit(Insn::new(MOV_X, 1, 2, 0, 0));
    b.emit(Insn::new(ADD_K, 1, 0, 0, 20));
    b.jump(Insn::new(JGT_X, 1, 0, 0, 0), Label::Drop);
    packet_load(b, None, HEADER, 20);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 10, HEADER + 12, 0));
    b.emit(Insn::new(RSH_K, 0, 0, 0, 4));
    b.jump(Insn::new(JLT_K, 0, 0, 0, 5), Label::Drop);
    b.emit(Insn::new(LSH_K, 0, 0, 0, 2));
    b.emit(Insn::new(LDX_W, 1, 10, OFFSET, 0));
    b.emit(Insn::new(ADD_X, 0, 1, 0, 0));
    b.emit(Insn::new(LDX_W, 1, 10, END, 0));
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 10, HEADER + 13, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0x17));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 2), Label::Drop);
}

fn packet_word(b: &mut Builder, reg: u8, offset: i16) {
    b.emit(Insn::new(LDX_W, reg, 9, offset, 0));
}

fn packet_load(b: &mut Builder, offset: Option<i32>, dest: i16, size: i32) {
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    if let Some(offset) = offset {
        b.emit(Insn::new(MOV_K, 2, 0, 0, offset));
    }
    stack(b, 3, dest);
    b.emit(Insn::new(MOV_K, 4, 0, 0, size));
    b.emit(Insn::new(CALL, 0, 0, 0, 26));
}

fn selector(c: &HostSourceConfig, maps: Maps, cast: u32) -> io::Result<Program> {
    let mut b = Builder::new();
    origin(&mut b, c, cast, true);
    gate(&mut b, maps.gate);
    b.emit(Insn::new(ST_W, 10, 0, DEVICE, 0));
    b.emit(Insn::new(LDX_W, 0, 10, M + 64, 0));
    b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
    lookup(&mut b, maps.returns, KEY);
    let unselected = ahead(&mut b, JEQ_K, 0, 0, 0);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    require(&mut b, LDX_W, 6, 12, 0);
    require(&mut b, LDX_W, 6, 28, 0);
    b.emit(Insn::new(LDX_W, 0, 6, 8, 0));
    b.emit(Insn::new(LDX_W, 1, 10, KEY, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_DW, 0, 6, 0, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(ST_W, 10, 0, DEVICE, 1));
    patch(&mut b, unselected);
    bank(&mut b, maps.sockets, maps.socket_locks);
    snapshot(&mut b);
    b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_TRANSITION as i32),
        Label::Drop,
    );
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_ENDPOINT as i32),
        Label::Selected,
    );
    b.emit(Insn::new(LDX_W, 1, 10, M + 72, 0));
    b.jump(Insn::new(0x16, 1, 0, 0, c.bypass_mark as i32), Label::Pass);
    b.emit(Insn::new(LDX_W, 1, 10, PROTOCOL, 0));
    b.jump(Insn::new(JEQ_K, 1, 0, 0, 17), Label::Options);
    b.jump(
        Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_BORN_NEW as i32),
        Label::Ipv4,
    );
    // Missing TCP claims mean only preexisting/passive work under mandatory connect-hook coverage.
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, HOST_SOCKET_CANDIDATE as i32),
        Label::Pass,
    );
    require(&mut b, LDX_W, 10, READY, 1);
    // Validate the actual first active-open header before selecting Endpoint. No ISN authority.
    b.emit(Insn::new(LDX_W, 0, 10, DEVICE, 0));
    let kernel = ahead(&mut b, JEQ_K, 0, 0, 0);
    first_syn(&mut b);
    patch(&mut b, kernel);
    // Serialize the first publication; a competing reader cannot choose another executor.
    bank_lock(&mut b, true);
    find_entry(&mut b);
    b.emit(Insn::new(MOV_K, 7, 0, 0, 0));
    let absent = ahead(&mut b, JEQ_K, 5, 0, 0);
    b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
    let changed = ahead(&mut b, JNE_K, 0, 0, HOST_SOCKET_CANDIDATE as i32);
    b.emit(Insn::new(LDX_DW, 0, 5, 40, 0));
    b.emit(Insn::new(LDX_DW, 1, 10, E + 40, 0));
    let replaced = ahead(&mut b, JNE_X, 0, 1, 0);
    b.emit(Insn::new(LDX_DW, 0, 10, GATE_POINTER, 0));
    b.emit(Insn::new(LDX_W, 0, 0, 0, 0));
    let closed = ahead(&mut b, JNE_K, 0, 0, 1);
    begin_write(&mut b, Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, DEVICE, 0));
    let choose_kernel = ahead(&mut b, JEQ_K, 0, 0, 0);
    b.emit(Insn::new(ST_W, 5, 0, 52, HOST_SOCKET_ENDPOINT as i32));
    b.emit(Insn::new(LDX_W, 0, 10, M + 64, 0));
    b.emit(Insn::new(STX_W, 5, 0, 56, 0));
    let chosen = ahead(&mut b, JA, 0, 0, 0);
    patch(&mut b, choose_kernel);
    b.emit(Insn::new(ST_W, 5, 0, 52, HOST_SOCKET_KERNEL as i32));
    patch(&mut b, chosen);
    end_write(&mut b);
    b.emit(Insn::new(MOV_K, 7, 0, 0, 1));
    patch(&mut b, absent);
    patch(&mut b, changed);
    patch(&mut b, replaced);
    patch(&mut b, closed);
    bank_lock(&mut b, false);
    b.jump(Insn::new(JEQ_K, 7, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);

    b.label(Label::Options);
    // An unselected UDP publication does not acquire Host custody.
    b.emit(Insn::new(LDX_W, 0, 10, DEVICE, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Ipv4);
    require(&mut b, LDX_W, 10, READY, 1);
    reserve(&mut b, maps.sequence);
    b.emit(Insn::new(LDX_DW, 7, 10, M + 48, 0));
    b.emit(Insn::new(LDX_DW, 8, 10, E + 8, 0));
    // Missing optional process entries still need the actual socket scalar.
    b.emit(Insn::new(LDX_DW, 0, 10, KSKB, 0));
    read_kernel(&mut b, 0, c.skb_sk_offset, 8, SCRATCH, Label::Drop);
    b.emit(Insn::new(LDX_DW, 8, 10, SCRATCH, 0));
    bank(&mut b, maps.sockets, maps.socket_locks);
    b.emit(Insn::new(ST_W, 10, 0, GOOD, 0));
    bank_lock(&mut b, true);
    find_entry(&mut b);
    let found = ahead(&mut b, JNE_K, 5, 0, 0);
    b.emit(Insn::new(MOV_X, 5, 4, 0, 0));
    let full = ahead(&mut b, JEQ_K, 5, 0, 0);
    patch(&mut b, found);
    b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
    b.emit(Insn::new(LDX_W, 1, 10, E + 52, 0));
    let changed = ahead(&mut b, JNE_X, 0, 1, 0);
    b.emit(Insn::new(LDX_DW, 0, 5, 40, 0));
    b.emit(Insn::new(LDX_DW, 1, 10, E + 40, 0));
    let changed_id = ahead(&mut b, JNE_X, 0, 1, 0);
    b.emit(Insn::new(LDX_DW, 0, 10, GATE_POINTER, 0));
    b.emit(Insn::new(LDX_W, 0, 0, 0, 0));
    let closed = ahead(&mut b, JNE_K, 0, 0, 1);
    begin_write(&mut b, Label::Drop);
    b.emit(Insn::new(LDX_DW, 0, 5, 0, 0));
    let existing = ahead(&mut b, JNE_K, 0, 0, 0);
    for off in (0..64).step_by(8) {
        b.emit(Insn::new(0x7a, 5, 0, off, 0));
    }
    b.emit(Insn::new(STX_DW, 5, 7, 0, 0));
    b.emit(Insn::new(STX_DW, 5, 8, 8, 0));
    patch(&mut b, existing);
    b.emit(Insn::new(LDX_DW, 0, 10, TOKEN, 0));
    b.emit(Insn::new(STX_DW, 5, 0, 40, 0));
    b.emit(Insn::new(ST_W, 5, 0, 52, HOST_SOCKET_TRANSITION as i32));
    end_write(&mut b);
    b.emit(Insn::new(ST_W, 10, 0, GOOD, 1));
    patch(&mut b, full);
    patch(&mut b, changed);
    patch(&mut b, changed_id);
    patch(&mut b, closed);
    bank_lock(&mut b, false);
    require(&mut b, LDX_W, 10, GOOD, 1);
    // Birth is causal first-publication proof, including a current zerocopy root's extra refs.
    b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
    let born = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_BORN_NEW as i32);
    b.emit(Insn::new(LDX_DW, 0, 10, KSKB, 0));
    read_kernel(
        &mut b,
        0,
        c.skb_destructor_offset,
        8,
        SCRATCH,
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_DW, 0, 10, SCRATCH, 0));
    imm(&mut b, 1, c.sock_wfree);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(LDX_DW, 0, 10, KSKB, 0));
    read_kernel(
        &mut b,
        0,
        c.skb_truesize_offset,
        4,
        SCRATCH,
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_W, 0, 10, SCRATCH, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    b.jump(Insn::new(0x16, 0, 0, 0, -1), Label::Malformed);
    b.emit(Insn::new(ADD_K, 0, 0, 0, 1));
    b.emit(Insn::new(STX_DW, 10, 0, POINTER, 0));
    read_kernel(
        &mut b,
        8,
        c.sock_write_queue_len_offset,
        4,
        SCRATCH,
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_W, 0, 10, SCRATCH, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    // The root is detached from the write queue; up.pending can describe THIS cork push.
    read_kernel(&mut b, 8, c.sock_wmem_offset, 4, SCRATCH, Label::Malformed);
    b.emit(Insn::new(LDX_W, 0, 10, SCRATCH, 0));
    b.emit(Insn::new(LDX_DW, 1, 10, POINTER, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    read_kernel(
        &mut b,
        8,
        c.sock_refcnt_offset,
        4,
        SCRATCH,
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_W, 0, 10, SCRATCH, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 1), Label::Malformed);
    patch(&mut b, born);
    // Probe/closed-gate failures restore the old executor but never publish this packet.
    gate(&mut b, maps.gate);
    b.emit(Insn::new(LDX_W, 0, 10, READY, 0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 1), Label::Malformed);
    b.emit(Insn::new(ST_W, 10, 0, GOOD, 1));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::CountDrop);
    b.label(Label::Malformed);
    b.emit(Insn::new(ST_W, 10, 0, GOOD, 0));
    b.label(Label::CountDrop);
    bank(&mut b, maps.sockets, maps.socket_locks);
    bank_lock(&mut b, true);
    find_entry(&mut b);
    b.emit(Insn::new(MOV_K, 7, 0, 0, 0));
    let missing = ahead(&mut b, JEQ_K, 5, 0, 0);
    b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
    let state_changed = ahead(&mut b, JNE_K, 0, 0, HOST_SOCKET_TRANSITION as i32);
    b.emit(Insn::new(LDX_DW, 0, 5, 40, 0));
    b.emit(Insn::new(LDX_DW, 1, 10, TOKEN, 0));
    let token_changed = ahead(&mut b, JNE_X, 0, 1, 0);
    begin_write(&mut b, Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, GOOD, 0));
    let abort = ahead(&mut b, JEQ_K, 0, 0, 0);
    b.emit(Insn::new(LDX_DW, 0, 10, GATE_POINTER, 0));
    b.emit(Insn::new(LDX_W, 0, 0, 0, 0));
    let closed = ahead(&mut b, JNE_K, 0, 0, 1);
    b.emit(Insn::new(ST_W, 5, 0, 52, HOST_SOCKET_ENDPOINT as i32));
    b.emit(Insn::new(LDX_W, 0, 10, M + 64, 0));
    b.emit(Insn::new(STX_W, 5, 0, 56, 0));
    b.emit(Insn::new(MOV_K, 7, 0, 0, 1));
    let committed = ahead(&mut b, JA, 0, 0, 0);
    patch(&mut b, abort);
    patch(&mut b, closed);
    b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
    b.emit(Insn::new(STX_W, 5, 0, 52, 0));
    b.emit(Insn::new(LDX_DW, 0, 10, E + 40, 0));
    b.emit(Insn::new(STX_DW, 5, 0, 40, 0));
    patch(&mut b, committed);
    end_write(&mut b);
    patch(&mut b, missing);
    patch(&mut b, state_changed);
    patch(&mut b, token_changed);
    bank_lock(&mut b, false);
    b.jump(Insn::new(JEQ_K, 7, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    b.label(Label::Ipv4);
    // Recheck under lock: a stale unselected snapshot must not pass a concurrent H/Transition.
    bank_lock(&mut b, true);
    find_entry(&mut b);
    b.emit(Insn::new(MOV_K, 7, 0, 0, 0));
    let no_record = ahead(&mut b, JEQ_K, 5, 0, 0);
    b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
    let host = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
    let transition = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_TRANSITION as i32);
    b.emit(Insn::new(LDX_W, 1, 10, E + 52, 0));
    let changed = ahead(&mut b, JNE_X, 0, 1, 0);
    b.emit(Insn::new(LDX_DW, 0, 5, 40, 0));
    b.emit(Insn::new(LDX_DW, 1, 10, E + 40, 0));
    let replaced = ahead(&mut b, JNE_X, 0, 1, 0);
    b.emit(Insn::new(LDX_DW, 0, 10, GATE_POINTER, 0));
    b.emit(Insn::new(LDX_W, 0, 0, 0, 0));
    b.emit(Insn::new(LDX_W, 1, 10, READY, 0));
    let closed = ahead(&mut b, JNE_X, 0, 1, 0);
    begin_write(&mut b, Label::Drop);
    b.emit(Insn::new(ST_W, 5, 0, 52, HOST_SOCKET_KERNEL as i32));
    end_write(&mut b);
    patch(&mut b, no_record);
    b.emit(Insn::new(MOV_K, 7, 0, 0, 1));
    patch(&mut b, host);
    patch(&mut b, transition);
    patch(&mut b, changed);
    patch(&mut b, replaced);
    patch(&mut b, closed);
    bank_lock(&mut b, false);
    b.jump(Insn::new(JEQ_K, 7, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    b.label(Label::Selected);
    require(&mut b, LDX_W, 10, DEVICE, 1);
    require(&mut b, LDX_W, 10, READY, 1);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    end(&mut b, true);
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_paths_unlock_before_helpers_and_terminal_actions() {
        let config = HostSourceConfig {
            source_netns: 1,
            attachment: 2,
            private_tx: 3,
            bypass_mark: 4,
            tx_mac: [2; 6],
            rx_mac: [4; 6],
            skb_sk_offset: 24,
            sock_net_pointer_offset: 48,
            net_cookie_offset: 64,
            skb_destructor_offset: 96,
            skb_truesize_offset: 104,
            sock_wmem_offset: 128,
            sock_refcnt_offset: 132,
            sock_write_queue_len_offset: 160,
            sock_wfree: 0xffff_ffff_8100_0000,
        };
        let maps = Maps {
            facts: 10,
            gate: 11,
            sequence: 12,
            sockets: 13,
            socket_locks: 15,
            returns: 14,
        };
        for program in [
            producer(&config, maps, 123, false).unwrap(),
            producer(&config, maps, 123, true).unwrap(),
            selector(&config, maps, 123).unwrap(),
        ] {
            let mut seen = vec![[false; 8]; program.len];
            let mut pending = vec![(0usize, false, false, false)];
            while let Some((pc, mut locked, mut mutated, mut publishing)) = pending.pop() {
                assert!(pc < program.len);
                let state =
                    usize::from(locked) + 2 * usize::from(mutated) + 4 * usize::from(publishing);
                if seen[pc][state] {
                    continue;
                }
                seen[pc][state] = true;
                let instruction = program.insns[pc];
                if instruction.code == CALL {
                    match instruction.imm {
                        93 => {
                            assert!(!locked);
                            locked = true;
                        }
                        94 => {
                            assert!(locked);
                            assert!(!publishing, "unlock before even bank publication at {pc}");
                            locked = false;
                        }
                        _ => assert!(!locked, "helper inside native lock at {pc}"),
                    }
                    mutated |= matches!(instruction.imm, 9 | 18);
                }
                if instruction.code == STX_DW && instruction.regs & 15 == 6 && instruction.off == 0
                {
                    assert!(locked, "version publication without external lock at {pc}");
                    publishing = !publishing;
                }
                if matches!(instruction.code & 7, 2 | 3) && instruction.regs & 15 == 5 {
                    assert!(
                        locked && publishing,
                        "entry write outside odd/even publication at {pc}"
                    );
                }
                if mutated && instruction.code == MOV_K && instruction.regs & 15 == 0 {
                    assert_ne!(instruction.imm, -1, "source NEXT after mutation");
                }
                if instruction.code == EXIT {
                    assert!(!locked, "exit holding native lock at {pc}");
                    continue;
                }
                if matches!(instruction.code & 7, 5 | 6) && instruction.code != CALL {
                    let target = (pc as isize + 1 + instruction.off as isize) as usize;
                    pending.push((target, locked, mutated, publishing));
                    if instruction.code == JA {
                        continue;
                    }
                }
                pending.push((
                    pc + if instruction.code == LD_MAP { 2 } else { 1 },
                    locked,
                    mutated,
                    publishing,
                ));
            }
        }
    }
}
