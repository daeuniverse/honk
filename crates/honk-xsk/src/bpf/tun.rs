//! Narrow TUN programs. All kernel offsets and tracing targets are admitted by core.
use super::*;
use honk_ebpf_common::{host::*, tun::*};

const DW: u8 = 0x79;
const SDW: u8 = 0x7b;
const ST64: u8 = 0x7a;
const JLT_X: u8 = 0xad;
const SUB_X: u8 = 0x1f;
const OR_K: u8 = 0x47;
const CMPXCHG: i32 = 0xf1;
const REC: i16 = -224;
const ENTRY: i16 = -288;
const OWNER: i16 = -304;
const SOCKET: i16 = -312;
const SKB: i16 = -320;
const DEV: i16 = -328;
const BANK: i16 = -336;
const LOCK: i16 = -344;
const TOKEN: i16 = -352;
const VERSION: i16 = -360;
const GATE: i16 = -368;
const WINDOW: i16 = -376;
const FILE: i16 = -384;
const TFILE: i16 = -392;
const TUN: i16 = -400;
const IOCB: i16 = -408;
const ITER: i16 = -416;
const TASK: i16 = -424;
const LEADER: i16 = -432;
const KEY: i16 = -440;
const TEMP: i16 = -456;
const COUNT: i16 = -464;

#[derive(Clone, Copy, Debug)]
pub struct TunProgramConfig {
    pub owner_epoch: u64,
    pub attachment: u64,
    pub netns_cookie: u64,
    pub ifindex: u32,
    pub bypass_mark: u32,
    pub owner_tgid: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TunKernelOffsets {
    pub cast: u32,
    pub skb_sk: u32,
    pub skb_dev: u32,
    pub skb_users: u32,
    pub skb_len: u32,
    pub skb_truesize: u32,
    pub skb_iif: u32,
    pub skb_cb: u32,
    pub skb_vlan_all: u32,
    pub skb_head: u32,
    pub skb_end: u32,
    pub shinfo_gso_size: u32,
    pub sock_state: u32,
    pub sock_family: u32,
    pub sock_type: u32,
    pub sock_protocol: u32,
    pub sock_mark: u32,
    pub sock_cookie: u32,
    pub sock_net: u32,
    pub sock_kernel_byte: u32,
    pub sock_kernel_mask: u32,
    pub net_cookie: u32,
    pub dev_ifindex: u32,
    pub dev_net: u32,
    pub iocb_file: u32,
    pub iocb_complete: u32,
    pub file_private: u32,
    pub file_flags: u32,
    pub tfile_tun: u32,
    pub tun_dev: u32,
    pub iter_ubuf: u32,
    pub tun_flags: u32,
    pub tun_numqueues: u32,
    pub tun_numdisabled: u32,
    pub tun_vnet_size: u32,
    pub tun_filter_prog: u32,
    pub tun_prog_program: u32,
    pub bpf_prog_aux: u32,
    pub bpf_prog_aux_id: u32,
    pub filter_id: u32,
    pub iter_count: u32,
    pub iter_type: u32,
    pub iter_source: u32,
    pub iter_nofault: u32,
    pub task_leader: u32,
    pub task_start: u32,
}

#[derive(Clone, Copy)]
pub struct TunTraceTarget {
    pub type_id: u32,
    /// Zero denotes vmlinux, otherwise this is the actual live module BTF FD.
    pub btf_fd: RawFd,
}

#[derive(Clone, Copy)]
pub struct TunMaps {
    pub sockets: RawFd,
    pub locks: RawFd,
    pub gate: RawFd,
    pub sequence: RawFd,
    pub packets: RawFd,
    pub free: RawFd,
    pub owner: RawFd,
    pub window: RawFd,
}

pub struct TunPrograms {
    fds: [OwnedFd; 8],
    ids: [u32; 8],
}

impl TunPrograms {
    pub const NAMES: [&'static str; 8] = [
        "tun_selector",
        "tun_filter",
        "tun_read_enter",
        "tun_copy_enter",
        "tun_copy_exit",
        "tun_read_exit",
        "tun_close_enter",
        "tun_close_exit",
    ];

    pub fn load(
        c: &TunProgramConfig,
        o: &TunKernelOffsets,
        m: TunMaps,
        read: TunTraceTarget,
        copy: TunTraceTarget,
        close: TunTraceTarget,
    ) -> io::Result<Self> {
        if !cfg!(all(target_arch = "x86_64", target_endian = "little"))
            || c.owner_epoch == 0
            || c.attachment == 0
            || c.netns_cookie == 0
            || c.ifindex == 0
            || c.bypass_mark == 0
            || c.owner_tgid == 0
            || o.cast == 0
            || read.type_id == 0
            || copy.type_id == 0
            || close.type_id == 0
        {
            return Err(invalid_data("unadmitted TUN program authority/layout"));
        }
        let mut log = vec![0; 1 << 20];
        let (selector, selector_id) =
            load_typed_program(&selector(c, o, m)?, b"honk_tun_sel", &mut log, 8, 1)?;
        let (filter, filter_id) =
            load_typed_program(&filter(c, o, m)?, b"honk_tun_filter", &mut log, 1, 0)?;
        let admitted = TunKernelOffsets { filter_id, ..*o };
        let o = &admitted;
        let (re, rei) = load_trace(
            &read_enter(c, o, m)?,
            b"honk_tun_read",
            read,
            false,
            &mut log,
        )?;
        let (ce, cei) = load_trace(
            &copy_enter(c, o, m)?,
            b"honk_tun_copy",
            copy,
            false,
            &mut log,
        )?;
        let (cx, cxi) = load_trace(&copy_exit(c, o, m)?, b"honk_tun_copx", copy, true, &mut log)?;
        let (rx, rxi) = load_trace(
            &read_exit(c, o, m)?,
            b"honk_tun_readx",
            read,
            true,
            &mut log,
        )?;
        let (cl, cli) = load_trace(
            &close_hook(c, o, m, false)?,
            b"honk_tun_close",
            close,
            false,
            &mut log,
        )?;
        let (clx, clxi) = load_trace(
            &close_hook(c, o, m, true)?,
            b"honk_tun_closx",
            close,
            true,
            &mut log,
        )?;
        Ok(Self {
            fds: [selector, filter, re, ce, cx, rx, cl, clx],
            ids: [selector_id, filter_id, rei, cei, cxi, rxi, cli, clxi],
        })
    }

    pub fn selector(&self) -> (BorrowedFd<'_>, u32) {
        (self.fds[0].as_fd(), self.ids[0])
    }
    pub fn filter(&self) -> (BorrowedFd<'_>, u32) {
        (self.fds[1].as_fd(), self.ids[1])
    }
    pub fn programs(&self) -> impl Iterator<Item = (&'static str, BorrowedFd<'_>, u32)> {
        Self::NAMES
            .into_iter()
            .zip(self.fds.iter().zip(self.ids))
            .map(|(name, (fd, id))| (name, fd.as_fd(), id))
    }
    pub fn attach_trace(&self, index: usize) -> io::Result<OwnedFd> {
        if !(2..8).contains(&index) {
            return Err(invalid_data("invalid TUN tracing program"));
        }
        #[repr(C)]
        struct Attr {
            name: u64,
            program: u32,
            padding: u32,
        }
        bpf_fd(
            17,
            &mut Attr {
                name: 0,
                program: self.fds[index].as_raw_fd() as u32,
                padding: 0,
            },
        )
    }
}

fn load_trace(
    p: &Program,
    name: &[u8],
    target: TunTraceTarget,
    exit: bool,
    log: &mut [u8],
) -> io::Result<(OwnedFd, u32)> {
    log.fill(0);
    let fd = bpf_fd(
        BPF_PROG_LOAD,
        &mut ProgLoadAttr {
            prog_type: 26,
            insn_cnt: p.len as u32,
            insns: p.insns.as_ptr() as u64,
            license: c"GPL".as_ptr() as u64,
            log_level: 1,
            log_size: log.len() as u32,
            log_buf: log.as_mut_ptr() as u64,
            prog_name: object_name(name),
            expected_attach_type: if exit { 25 } else { 24 },
            attach_btf_id: target.type_id,
            // Kernel union with `attach_btf_obj_fd` for module BTF targets.
            attach_prog_fd: target.btf_fd.max(0) as u32,
            ..Default::default()
        },
    )
    .map_err(|error| {
        let length = log.iter().position(|&x| x == 0).unwrap_or(log.len());
        io::Error::new(
            error.kind(),
            format!(
                "TUN tracing load {}: {error}\n{}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(&log[..length])
            ),
        )
    })?;
    let mut info = ProgInfo::default();
    object_info(fd.as_fd(), &mut info)?;
    if info.kind != 26 || info.id == 0 {
        return Err(invalid_data("TUN tracing program readback mismatch"));
    }
    Ok((fd, info.id))
}

fn imm(b: &mut Builder, dst: u8, value: u64) {
    b.emit(Insn::new(LD_MAP, dst, 0, 0, value as i32));
    b.emit(Insn::new(0, 0, 0, 0, (value >> 32) as i32));
}
fn stack(b: &mut Builder, dst: u8, offset: i16) {
    b.emit(Insn::new(MOV_X, dst, 10, 0, 0));
    b.emit(Insn::new(ADD_K, dst, 0, 0, offset as i32));
}
fn ahead(b: &mut Builder, code: u8, dst: u8, src: u8, value: i32) -> usize {
    b.emit(Insn::new(code, dst, src, 0, value))
}
fn patch(b: &mut Builder, at: usize) {
    b.program.insns[at].off = (b.program.len - at - 1) as i16;
}
fn lookup(b: &mut Builder, fd: RawFd) {
    b.map_fd(fd);
    stack(b, 2, KEY);
    b.emit(Insn::new(CALL, 0, 0, 0, 1));
}
fn zero_key(b: &mut Builder) {
    b.emit(Insn::new(ST_W, 10, 0, KEY, 0));
}
fn read(b: &mut Builder, base: u8, offset: u32, width: i32, dest: i16, fail: Label) {
    b.emit(Insn::new(MOV_X, 3, base, 0, 0));
    b.emit(Insn::new(ADD_K, 3, 0, 0, offset as i32));
    stack(b, 1, dest);
    b.emit(Insn::new(MOV_K, 2, 0, 0, width));
    b.emit(Insn::new(CALL, 0, 0, 0, 113));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), fail);
}
fn arg(b: &mut Builder, index: u32, dst: u8, fail: Label) {
    read(b, 9, index * 8, 8, TEMP, fail);
    b.emit(Insn::new(DW, dst, 10, TEMP, 0));
}
fn scalar(b: &mut Builder, reg: u8, dest: i16, fail: Label) {
    b.emit(Insn::new(SDW, 10, reg, TEMP, 0));
    stack(b, 3, TEMP);
    stack(b, 1, dest);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 8));
    b.emit(Insn::new(CALL, 0, 0, 0, 113));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), fail);
}
fn check(b: &mut Builder, code: u8, base: u8, offset: i16, expected: i32, fail: Label) {
    b.emit(Insn::new(code, 0, base, offset, 0));
    b.jump(
        Insn::new(
            if code == LDX_W { JNE32_K } else { JNE_K },
            0,
            0,
            0,
            expected,
        ),
        fail,
    );
}
fn equal64(b: &mut Builder, base: u8, offset: i16, value: u64, fail: Label) {
    b.emit(Insn::new(DW, 0, base, offset, 0));
    imm(b, 1, value);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), fail);
}
fn saved(b: &mut Builder, dst: u8, slot: i16) {
    b.emit(Insn::new(DW, dst, 10, slot, 0));
}
fn copy_words(b: &mut Builder, dst: u8, dstoff: i16, src: u8, srcoff: i16, bytes: i16) {
    for off in (0..bytes).step_by(8) {
        b.emit(Insn::new(DW, 0, src, srcoff + off, 0));
        b.emit(Insn::new(SDW, dst, 0, dstoff + off, 0));
    }
}
fn lock(b: &mut Builder, reg: u8, acquire: bool) {
    b.emit(Insn::new(MOV_X, 1, reg, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, if acquire { 93 } else { 94 }));
}
fn cas(b: &mut Builder, base: u8, offset: i16, expected: u64, desired: u64, fail: Label) {
    imm(b, 0, expected);
    imm(b, 1, desired);
    b.emit(Insn::new(ATOMIC_ADD_DW, base, 1, offset, CMPXCHG));
    b.jump(Insn::new(JNE_K, 0, 0, 0, expected as i32), fail);
}
fn owner(b: &mut Builder, c: &TunProgramConfig, m: TunMaps, open: bool, fail: Label) {
    zero_key(b);
    lookup(b, m.owner);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(SDW, 10, 0, OWNER, 0));
    b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
    check(b, LDX_W, 8, 0, TUN_ABI_MAGIC as i32, fail);
    check(
        b,
        LDX_W,
        8,
        4,
        ((TUN_OWNER_EXTENT as u32) << 16 | u32::from(TUN_ABI_VERSION)) as i32,
        fail,
    );
    equal64(b, 8, 24, c.owner_epoch, fail);
    equal64(b, 8, 32, c.attachment, fail);
    equal64(b, 8, 40, c.netns_cookie, fail);
    check(b, LDX_W, 8, 128, c.ifindex as i32, fail);
    if open {
        equal64(b, 8, 8, 1, fail);
        equal64(b, 8, 16, 0, fail);
    }
}
fn gate(b: &mut Builder, m: TunMaps, fail: Label) {
    zero_key(b);
    lookup(b, m.gate);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), fail);
    b.emit(Insn::new(SDW, 10, 0, GATE, 0));
    check(b, LDX_W, 0, 0, 1, fail);
}
fn fault(b: &mut Builder, bits: u64) {
    saved(b, 8, OWNER);
    imm(b, 1, bits);
    b.emit(Insn::new(ATOMIC_ADD_DW, 8, 1, 16, 0x40));
    b.emit(Insn::new(ST64, 8, 0, 8, 0));
}
fn end(b: &mut Builder, selector: bool) {
    b.label(Label::Pass);
    b.emit(Insn::new(MOV_K, 0, 0, 0, if selector { 1 } else { 0 }));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
}

// Context writes are confined to the filter's documented five-word BPF CB region.
fn origin(b: &mut Builder, c: &TunProgramConfig, o: &TunKernelOffsets, selector: bool) {
    b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
    b.emit(Insn::new(CALL, 0, 2, 0, o.cast as i32));
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    scalar(b, 6, SKB, Label::Drop);
    read(b, 6, o.skb_dev, 8, DEV, Label::Drop);
    saved(b, 8, DEV);
    b.jump(
        Insn::new(JEQ_K, 8, 0, 0, 0),
        if selector { Label::Pass } else { Label::Drop },
    );
    read(b, 8, o.dev_ifindex, 4, TEMP, Label::Drop);
    check(
        b,
        LDX_W,
        10,
        TEMP,
        c.ifindex as i32,
        if selector { Label::Pass } else { Label::Drop },
    );
    read(b, 8, o.dev_net, 8, TEMP, Label::Drop);
    saved(b, 8, TEMP);
    read(b, 8, o.net_cookie, 8, TEMP, Label::Drop);
    equal64(b, 10, TEMP, c.netns_cookie, Label::Drop);
    read(b, 6, o.skb_sk, 8, SOCKET, Label::Drop);
    saved(b, 8, SOCKET);
    b.jump(Insn::new(JEQ_K, 8, 0, 0, 0), Label::Options);
    read(b, 8, o.sock_state, 1, TEMP, Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 10, TEMP, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 6), Label::Options);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 12), Label::Options);
    read(b, 8, o.sock_family, 2, REC + 150, Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 10, REC + 150, 0));
    let v4 = ahead(b, JEQ_K, 0, 0, 2);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 10), Label::Options);
    patch(b, v4);
    read(b, 8, o.sock_kernel_byte, 1, TEMP, Label::Drop);
    b.emit(Insn::new(LDX_B, 0, 10, TEMP, 0));
    b.jump(
        Insn::new(JSET_K, 0, 0, 0, o.sock_kernel_mask as i32),
        Label::Options,
    );
    read(b, 8, o.sock_protocol, 2, TEMP, Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 10, TEMP, 0));
    let udp = ahead(b, JEQ_K, 0, 0, 17);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 6), Label::Options);
    read(b, 8, o.sock_type, 2, TEMP, Label::Drop);
    check(b, LDX_H, 10, TEMP, 1, Label::Options);
    let tcp_done = ahead(b, JA, 0, 0, 0);
    patch(b, udp);
    read(b, 8, o.sock_type, 2, TEMP, Label::Drop);
    check(b, LDX_H, 10, TEMP, 2, Label::Options);
    patch(b, tcp_done);
    read(b, 8, o.sock_net, 8, TEMP, Label::Drop);
    saved(b, 7, TEMP);
    read(b, 7, o.net_cookie, 8, TEMP, Label::Drop);
    equal64(b, 10, TEMP, c.netns_cookie, Label::Drop);
    read(b, 8, o.sock_mark, 4, REC + 120, Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, REC + 120, 0));
    b.jump(
        Insn::new(0x16, 0, 0, 0, c.bypass_mark as i32),
        if selector { Label::Pass } else { Label::Drop },
    );
    if selector {
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(CALL, 0, 0, 0, 46));
        b.emit(Insn::new(MOV_X, 7, 0, 0, 0));
    } else {
        read(b, 8, o.sock_cookie, 8, TEMP, Label::Drop);
        saved(b, 7, TEMP);
    }
    b.jump(Insn::new(JEQ_K, 7, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(SDW, 10, 7, REC + 96, 0));
}
fn bank(b: &mut Builder, m: TunMaps, locking: bool) {
    b.emit(Insn::new(MOV_X, 0, 7, 0, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, (HOST_SOCKET_BUCKETS - 1) as i32));
    b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
    lookup(b, m.sockets);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(SDW, 10, 0, BANK, 0));
    if locking {
        lookup(b, m.locks);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(SDW, 10, 0, LOCK, 0));
    }
    saved(b, 6, BANK);
    saved(b, 8, SOCKET);
}
fn find_entry(b: &mut Builder) {
    b.emit(Insn::new(MOV_K, 5, 0, 0, 0));
    b.emit(Insn::new(MOV_K, 4, 0, 0, 0));
    for way in 0..8i16 {
        let off = 8 + way * 64;
        b.emit(Insn::new(DW, 0, 6, off, 0));
        let occupied = ahead(b, JNE_K, 0, 0, 0);
        let have_empty = ahead(b, JNE_K, 4, 0, 0);
        b.emit(Insn::new(MOV_X, 4, 6, 0, 0));
        b.emit(Insn::new(ADD_K, 4, 0, 0, off as i32));
        patch(b, occupied);
        patch(b, have_empty);
        let cookie = ahead(b, JNE_X, 0, 7, 0);
        b.emit(Insn::new(DW, 0, 6, off + 8, 0));
        let address = ahead(b, JNE_X, 0, 8, 0);
        b.emit(Insn::new(MOV_X, 5, 6, 0, 0));
        b.emit(Insn::new(ADD_K, 5, 0, 0, off as i32));
        patch(b, cookie);
        patch(b, address);
    }
}
fn selector(c: &TunProgramConfig, o: &TunKernelOffsets, m: TunMaps) -> io::Result<Program> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    for off in (REC..REC + 192).step_by(8) {
        b.emit(Insn::new(ST64, 10, 0, off, 0));
    }
    origin(&mut b, c, o, true);
    owner(&mut b, c, m, true, Label::Drop);
    gate(&mut b, m, Label::Drop);
    saved(&mut b, 7, REC + 96);
    bank(&mut b, m, true);
    saved(&mut b, 1, LOCK);
    lock(&mut b, 1, true);
    find_entry(&mut b);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    let absent = ahead(&mut b, JEQ_K, 5, 0, 0);
    b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
    let unselected = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_UNSELECTED as i32);
    let born = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_BORN_NEW as i32);
    let foreign = ahead(&mut b, JNE_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
    b.emit(Insn::new(LDX_W, 0, 5, 56, 0));
    let wrong = ahead(&mut b, JNE_K, 0, 0, c.ifindex as i32);
    b.emit(Insn::new(DW, 0, 5, 40, 0));
    let zero = ahead(&mut b, JEQ_K, 0, 0, 0);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 1));
    let selected = ahead(&mut b, JA, 0, 0, 0);
    patch(&mut b, absent);
    patch(&mut b, unselected);
    patch(&mut b, born);
    b.emit(Insn::new(MOV_K, 2, 0, 0, 2));
    patch(&mut b, selected);
    patch(&mut b, foreign);
    patch(&mut b, wrong);
    patch(&mut b, zero);
    b.emit(Insn::new(STX_W, 10, 2, COUNT, 0));
    saved(&mut b, 1, LOCK);
    lock(&mut b, 1, false);
    check(&mut b, LDX_W, 10, COUNT, 0, Label::Ipv4);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
    b.label(Label::Ipv4);
    b.emit(Insn::new(LDX_W, 0, 10, COUNT, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 1), Label::Pass);
    zero_key(&mut b);
    lookup(&mut b, m.sequence);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    lock(&mut b, 6, true);
    b.emit(Insn::new(DW, 7, 6, 8, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
    let exhausted_zero = ahead(&mut b, JEQ_K, 7, 0, 0);
    imm(&mut b, 1, HOST_ID_MAX);
    let exhausted_max = ahead(&mut b, JGT_X, 7, 1, 0);
    b.emit(Insn::new(MOV_X, 0, 7, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 1));
    b.emit(Insn::new(SDW, 6, 0, 8, 0));
    b.emit(Insn::new(MOV_K, 2, 0, 0, 1));
    patch(&mut b, exhausted_zero);
    patch(&mut b, exhausted_max);
    b.emit(Insn::new(SDW, 10, 7, TOKEN, 0));
    b.emit(Insn::new(STX_W, 10, 2, COUNT, 0));
    lock(&mut b, 6, false);
    b.emit(Insn::new(LDX_W, 0, 10, COUNT, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    saved(&mut b, 7, REC + 96);
    saved(&mut b, 6, BANK);
    saved(&mut b, 8, SOCKET);
    saved(&mut b, 1, LOCK);
    lock(&mut b, 1, true);
    find_entry(&mut b);
    b.emit(Insn::new(MOV_K, 3, 0, 0, 0));
    let found = ahead(&mut b, JNE_K, 5, 0, 0);
    b.emit(Insn::new(MOV_X, 5, 4, 0, 0));
    let full = ahead(&mut b, JEQ_K, 5, 0, 0);
    patch(&mut b, found);
    b.emit(Insn::new(DW, 0, 6, 0, 0));
    b.emit(Insn::new(MOV_X, 2, 0, 0, 0));
    let odd = ahead(&mut b, JSET_K, 0, 0, 1);
    imm(&mut b, 1, u64::MAX - 2);
    let overflow = ahead(&mut b, JGT_X, 0, 1, 0);
    b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
    let fresh = ahead(&mut b, JEQ_K, 0, 0, 0);
    let newborn = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_BORN_NEW as i32);
    let already = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
    let inconsistent = ahead(&mut b, JA, 0, 0, 0);
    patch(&mut b, fresh);
    patch(&mut b, newborn);
    saved(&mut b, 1, GATE);
    b.emit(Insn::new(LDX_W, 0, 1, 0, 0));
    let closed = ahead(&mut b, JNE_K, 0, 0, 1);
    b.emit(Insn::new(MOV_X, 0, 2, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 1));
    b.emit(Insn::new(SDW, 6, 0, 0, 0));
    b.emit(Insn::new(SDW, 5, 7, 0, 0));
    b.emit(Insn::new(SDW, 5, 8, 8, 0));
    saved(&mut b, 0, TOKEN);
    b.emit(Insn::new(SDW, 5, 0, 40, 0));
    b.emit(Insn::new(ST_W, 5, 0, 52, HOST_SOCKET_ENDPOINT as i32));
    b.emit(Insn::new(ST_W, 5, 0, 56, c.ifindex as i32));
    b.emit(Insn::new(ADD_K, 2, 0, 0, 2));
    b.emit(Insn::new(SDW, 6, 2, 0, 0));
    patch(&mut b, already);
    b.emit(Insn::new(LDX_W, 0, 5, 56, 0));
    let changed_output = ahead(&mut b, JNE_K, 0, 0, c.ifindex as i32);
    b.emit(Insn::new(DW, 0, 5, 40, 0));
    let missing_token = ahead(&mut b, JEQ_K, 0, 0, 0);
    imm(&mut b, 1, HOST_ID_MAX);
    let invalid_token = ahead(&mut b, JGT_X, 0, 1, 0);
    b.emit(Insn::new(MOV_K, 3, 0, 0, 1));
    let selected_done = ahead(&mut b, JA, 0, 0, 0);
    patch(&mut b, overflow);
    b.emit(Insn::new(MOV_K, 3, 0, 0, 2));
    patch(&mut b, selected_done);
    patch(&mut b, inconsistent);
    patch(&mut b, closed);
    patch(&mut b, full);
    patch(&mut b, odd);
    patch(&mut b, changed_output);
    patch(&mut b, missing_token);
    patch(&mut b, invalid_token);
    b.emit(Insn::new(STX_W, 10, 3, COUNT, 0));
    saved(&mut b, 1, LOCK);
    lock(&mut b, 1, false);
    b.emit(Insn::new(LDX_W, 0, 10, COUNT, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 2), Label::Malformed);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    b.label(Label::Malformed);
    fault(&mut b, TUN_FATAL_EXHAUSTED);
    saved(&mut b, 1, GATE);
    b.emit(Insn::new(ST_W, 1, 0, 0, 0));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
    b.label(Label::Options);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    end(&mut b, true);
    b.finish()
}

fn filter(c: &TunProgramConfig, o: &TunKernelOffsets, m: TunMaps) -> io::Result<Program> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    for off in (REC..REC + 192).step_by(8) {
        b.emit(Insn::new(ST64, 10, 0, off, 0));
    }
    b.emit(Insn::new(ST64, 10, 0, OWNER, 0));
    owner(&mut b, c, m, true, Label::Drop);
    gate(&mut b, m, Label::Drop);
    origin(&mut b, c, o, false);
    bank(&mut b, m, false);
    b.emit(Insn::new(DW, 0, 6, 0, 0));
    b.jump(Insn::new(JSET_K, 0, 0, 0, 1), Label::Drop);
    b.emit(Insn::new(SDW, 10, 0, VERSION, 0));
    find_entry(&mut b);
    b.jump(Insn::new(JEQ_K, 5, 0, 0, 0), Label::Drop);
    copy_words(&mut b, 10, ENTRY, 5, 0, 64);
    b.emit(Insn::new(DW, 0, 6, 0, 0));
    saved(&mut b, 1, VERSION);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    check(
        &mut b,
        LDX_W,
        10,
        ENTRY + 52,
        HOST_SOCKET_ENDPOINT as i32,
        Label::Drop,
    );
    check(&mut b, LDX_W, 10, ENTRY + 56, c.ifindex as i32, Label::Drop);
    saved(&mut b, 0, ENTRY + 40);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    imm(&mut b, 1, HOST_ID_MAX);
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(SDW, 10, 0, REC + 152, 0));
    b.emit(Insn::new(LDX_W, 0, 10, ENTRY + 36, 0));
    b.jump(
        Insn::new(JSET_K, 0, 0, 0, !(HOST_SOCKET_PROCESS_PRESENT as i32)),
        Label::Drop,
    );
    b.emit(Insn::new(LSH_K, 0, 0, 0, 1));
    b.emit(Insn::new(OR_K, 0, 0, 0, HOST_SOURCE_LOCAL as i32));
    b.emit(Insn::new(STX_W, 10, 0, REC + 144, 0));
    b.emit(Insn::new(LDX_W, 0, 10, ENTRY + 16, 0));
    b.emit(Insn::new(STX_W, 10, 0, REC + 124, 0));
    for off in (0..16).step_by(4) {
        b.emit(Insn::new(LDX_W, 0, 10, ENTRY + 20 + off, 0));
        b.emit(Insn::new(STX_W, 10, 0, REC + 128 + off, 0));
    }
    imm(&mut b, 0, c.netns_cookie);
    b.emit(Insn::new(SDW, 10, 0, REC + 80, 0));
    imm(&mut b, 0, c.attachment);
    b.emit(Insn::new(SDW, 10, 0, REC + 88, 0));
    b.emit(Insn::new(SDW, 10, 0, REC + 104, 0));
    b.emit(Insn::new(ST_W, 10, 0, REC + 112, c.ifindex as i32));
    b.emit(Insn::new(LDX_W, 0, 9, 8, 0));
    b.emit(Insn::new(STX_W, 10, 0, REC + 116, 0));
    b.emit(Insn::new(
        0x6a,
        10,
        0,
        REC + 148,
        HOST_STAGE_TUN_EGRESS as i32,
    ));
    b.emit(Insn::new(ST_W, 10, 0, REC + 72, TUN_SOURCE_HOST as i32));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Selected);
    b.label(Label::Options);
    for off in (80..160).step_by(8) {
        b.emit(Insn::new(ST64, 10, 0, REC + off, 0));
    }
    b.label(Label::Selected);
    saved(&mut b, 6, SKB);
    read(&mut b, 6, o.skb_users, 4, TEMP, Label::Drop);
    check(&mut b, LDX_W, 10, TEMP, 1, Label::Drop);
    read(&mut b, 6, o.skb_vlan_all, 4, TEMP, Label::Drop);
    check(&mut b, LDX_W, 10, TEMP, 0, Label::Drop);
    saved(&mut b, 8, OWNER);
    b.emit(Insn::new(DW, 0, 8, 80, 0));
    saved(&mut b, 1, DEV);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    read(&mut b, 6, o.skb_len, 4, REC + 68, Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, REC + 68, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JGT_K, 0, 0, 0, i32::MAX - 10), Label::Drop);
    read(&mut b, 6, o.skb_truesize, 4, REC + 160, Label::Drop);
    read(&mut b, 6, o.skb_iif, 4, REC + 164, Label::Drop);
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        REC + 76,
        HOST_REPRESENTATION_MATERIALIZED as i32,
    ));
    read(&mut b, 6, o.skb_head, 8, TEMP, Label::Drop);
    saved(&mut b, 7, TEMP);
    read(&mut b, 6, o.skb_end, 4, TEMP, Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, TEMP, 0));
    b.emit(Insn::new(ADD_X, 7, 0, 0, 0));
    read(&mut b, 7, o.shinfo_gso_size, 2, TEMP, Label::Drop);
    b.emit(Insn::new(LDX_H, 0, 10, TEMP, 0));
    let nongso = ahead(&mut b, JEQ_K, 0, 0, 0);
    b.emit(Insn::new(
        ST_W,
        10,
        0,
        REC + 76,
        HOST_REPRESENTATION_GSO as i32,
    ));
    patch(&mut b, nongso);
    b.emit(Insn::new(CALL, 0, 0, 0, 5));
    b.emit(Insn::new(SDW, 10, 0, REC + 32, 0));
    imm(&mut b, 1, HOST_CAPTURE_HORIZON_NS);
    b.emit(Insn::new(ADD_X, 0, 1, 0, 0));
    saved(&mut b, 1, REC + 32);
    b.jump(Insn::new(JLT_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(SDW, 10, 0, REC + 40, 0));
    saved(&mut b, 8, OWNER);
    b.emit(Insn::new(DW, 0, 8, 48, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    imm(&mut b, 1, HOST_ID_MAX);
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(SDW, 10, 0, TOKEN, 0));
    b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
    b.emit(Insn::new(ADD_K, 1, 0, 0, 1));
    b.emit(Insn::new(ATOMIC_ADD_DW, 8, 1, 48, CMPXCHG));
    saved(&mut b, 1, TOKEN);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(SDW, 10, 0, REC + 8, 0));
    b.map_fd(m.free);
    stack(&mut b, 2, KEY);
    b.emit(Insn::new(CALL, 0, 0, 0, 88));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(LDX_W, 0, 10, KEY, 0));
    b.jump(
        Insn::new(JGE_K, 0, 0, 0, TUN_PACKET_CELLS as i32),
        Label::Malformed,
    );
    lookup(&mut b, m.packets);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 7, 0, 0, 0));
    cas(
        &mut b,
        7,
        0,
        TUN_PACKET_FREE,
        TUN_PACKET_WRITING,
        Label::Malformed,
    );
    imm(&mut b, 0, c.owner_epoch);
    b.emit(Insn::new(SDW, 10, 0, REC + 16, 0));
    saved(&mut b, 0, SKB);
    b.emit(Insn::new(SDW, 10, 0, REC + 24, 0));
    imm(&mut b, 0, c.attachment);
    b.emit(Insn::new(SDW, 10, 0, REC + 48, 0));
    imm(&mut b, 0, c.netns_cookie);
    b.emit(Insn::new(SDW, 10, 0, REC + 56, 0));
    b.emit(Insn::new(ST_W, 10, 0, REC + 64, c.ifindex as i32));
    copy_words(&mut b, 7, 8, 10, REC + 8, 184);
    cas(
        &mut b,
        7,
        0,
        TUN_PACKET_WRITING,
        TUN_PACKET_LIVE,
        Label::Malformed,
    );
    b.emit(Insn::new(ST_W, 9, 0, 48, TUN_STAMP_MAGIC as i32));
    saved(&mut b, 0, TOKEN);
    b.emit(Insn::new(STX_W, 9, 0, 52, 0));
    b.emit(Insn::new(RSH_K, 0, 0, 0, 32));
    b.emit(Insn::new(STX_W, 9, 0, 56, 0));
    b.emit(Insn::new(LDX_W, 0, 10, KEY, 0));
    b.emit(Insn::new(STX_W, 9, 0, 60, 0));
    b.emit(Insn::new(ST_W, 9, 0, 64, c.attachment as u32 as i32));
    saved(&mut b, 8, OWNER);
    equal64(&mut b, 8, 8, 1, Label::Drop);
    equal64(&mut b, 8, 16, 0, Label::Drop);
    saved(&mut b, 1, GATE);
    check(&mut b, LDX_W, 1, 0, 1, Label::Drop);
    b.emit(Insn::new(MOV_K, 1, 0, 0, 1));
    b.emit(Insn::new(ATOMIC_ADD_DW, 8, 1, 152, 0));
    b.emit(Insn::new(LDX_W, 0, 9, 0, 0));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Malformed);
    fault(&mut b, TUN_FATAL_OWNERSHIP | TUN_FATAL_EXHAUSTED);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
    b.label(Label::Drop);
    saved(&mut b, 8, OWNER);
    let no_owner = ahead(&mut b, JEQ_K, 8, 0, 0);
    b.emit(Insn::new(MOV_K, 1, 0, 0, 1));
    b.emit(Insn::new(ATOMIC_ADD_DW, 8, 1, 144, 0));
    patch(&mut b, no_owner);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

fn trace_window(b: &mut Builder, c: &TunProgramConfig, m: TunMaps) {
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    owner(b, c, m, false, Label::Drop);
    zero_key(b);
    lookup(b, m.window);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.emit(Insn::new(MOV_X, 7, 0, 0, 0));
    b.emit(Insn::new(SDW, 10, 7, WINDOW, 0));
    check(b, LDX_W, 7, 0, TUN_ABI_MAGIC as i32, Label::Drop);
    check(
        b,
        LDX_W,
        7,
        4,
        ((TUN_WINDOW_EXTENT as u32) << 16 | u32::from(TUN_ABI_VERSION)) as i32,
        Label::Drop,
    );
    equal64(b, 7, 24, c.owner_epoch, Label::Drop);
    equal64(b, 7, 32, c.attachment, Label::Drop);
    equal64(b, 7, 40, c.netns_cookie, Label::Drop);
    check(b, LDX_W, 7, 64, c.ifindex as i32, Label::Drop);
    check(b, LDX_W, 7, 244, c.owner_tgid as i32, Label::Drop);
    b.emit(Insn::new(CALL, 0, 0, 0, 14));
    b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
    b.emit(Insn::new(RSH_K, 1, 0, 0, 32));
    b.jump(Insn::new(JNE_K, 1, 0, 0, c.owner_tgid as i32), Label::Drop);
    b.emit(Insn::new(0xbc, 0, 0, 0, 0));
    b.emit(Insn::new(LDX_W, 1, 7, 68, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
}
fn task(b: &mut Builder, o: &TunKernelOffsets, first: bool) {
    b.emit(Insn::new(CALL, 0, 0, 0, 35));
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    b.emit(Insn::new(SDW, 10, 6, TASK, 0));
    if first {
        b.emit(Insn::new(SDW, 7, 6, 72, 0));
    } else {
        b.emit(Insn::new(DW, 0, 7, 72, 0));
        b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Malformed);
    }
    read(b, 6, o.task_start, 8, TEMP, Label::Malformed);
    saved(b, 0, TEMP);
    if first {
        b.emit(Insn::new(SDW, 7, 0, 336, 0));
    } else {
        b.emit(Insn::new(DW, 1, 7, 336, 0));
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    }
    read(b, 6, o.task_leader, 8, LEADER, Label::Malformed);
    saved(b, 6, LEADER);
    read(b, 6, o.task_start, 8, TEMP, Label::Malformed);
    saved(b, 0, TEMP);
    if first {
        b.emit(Insn::new(SDW, 7, 0, 80, 0));
    } else {
        b.emit(Insn::new(DW, 1, 7, 80, 0));
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    }
}
fn window_fault(b: &mut Builder) {
    fault(b, TUN_FATAL_GEOMETRY);
    saved(b, 7, WINDOW);
    imm(b, 1, TUN_FATAL_GEOMETRY);
    b.emit(Insn::new(ATOMIC_ADD_DW, 7, 1, 16, 0x40));
    b.emit(Insn::new(
        ST_W,
        7,
        0,
        240,
        TUN_STATUS_INTEGRITY_FAILURE as i32,
    ));
}
fn read_enter(c: &TunProgramConfig, o: &TunKernelOffsets, m: TunMaps) -> io::Result<Program> {
    let mut b = Builder::new();
    trace_window(&mut b, c, m);
    equal64(&mut b, 7, 16, 0, Label::Drop);
    equal64(&mut b, 7, 8, TUN_PHASE_ARMED, Label::Drop);
    b.emit(Insn::new(DW, 0, 7, 48, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    imm(&mut b, 1, HOST_ID_MAX);
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
    b.emit(Insn::new(DW, 1, 7, 328, 0));
    b.jump(Insn::new(0xbd, 0, 1, 0, 0), Label::Drop);
    cas(
        &mut b,
        7,
        8,
        TUN_PHASE_ARMED,
        TUN_PHASE_ENTERED,
        Label::Drop,
    );
    arg(&mut b, 0, 6, Label::Malformed);
    b.emit(Insn::new(SDW, 10, 6, IOCB, 0));
    b.emit(Insn::new(SDW, 7, 6, 112, 0));
    arg(&mut b, 1, 6, Label::Malformed);
    b.emit(Insn::new(SDW, 10, 6, ITER, 0));
    b.emit(Insn::new(SDW, 7, 6, 120, 0));
    task(&mut b, o, true);
    saved(&mut b, 6, IOCB);
    read(&mut b, 6, o.iocb_complete, 8, TEMP, Label::Malformed);
    equal64(&mut b, 10, TEMP, 0, Label::Malformed);
    read(&mut b, 6, o.iocb_file, 8, FILE, Label::Malformed);
    saved(&mut b, 6, FILE);
    b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(SDW, 7, 6, 88, 0));
    read(&mut b, 6, o.file_flags, 4, TEMP, Label::Malformed);
    b.emit(Insn::new(LDX_W, 0, 10, TEMP, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, libc::O_NONBLOCK));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    read(&mut b, 6, o.file_private, 8, TFILE, Label::Malformed);
    saved(&mut b, 6, TFILE);
    b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(SDW, 7, 6, 96, 0));
    read(&mut b, 6, o.tfile_tun, 8, TUN, Label::Malformed);
    saved(&mut b, 6, TUN);
    b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(SDW, 7, 6, 104, 0));
    read(&mut b, 6, o.tun_flags, 4, TEMP, Label::Malformed);
    b.emit(Insn::new(LDX_W, 0, 10, TEMP, 0));
    b.emit(Insn::new(STX_W, 10, 0, COUNT, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0x5903));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x5001), Label::Malformed);
    read(&mut b, 6, o.tun_numqueues, 4, TEMP, Label::Malformed);
    check(&mut b, LDX_W, 10, TEMP, 1, Label::Malformed);
    read(&mut b, 6, o.tun_numdisabled, 4, TEMP, Label::Malformed);
    check(&mut b, LDX_W, 10, TEMP, 0, Label::Malformed);
    read(&mut b, 6, o.tun_vnet_size, 4, TEMP, Label::Malformed);
    check(&mut b, LDX_W, 10, TEMP, 10, Label::Malformed);
    read(&mut b, 6, o.tun_dev, 8, DEV, Label::Malformed);
    saved(&mut b, 6, DEV);
    b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Malformed);
    read(&mut b, 6, o.dev_ifindex, 4, TEMP, Label::Malformed);
    check(&mut b, LDX_W, 10, TEMP, c.ifindex as i32, Label::Malformed);
    read(&mut b, 6, o.dev_net, 8, TEMP, Label::Malformed);
    saved(&mut b, 6, TEMP);
    read(&mut b, 6, o.net_cookie, 8, TEMP, Label::Malformed);
    equal64(&mut b, 10, TEMP, c.netns_cookie, Label::Malformed);
    saved(&mut b, 8, OWNER);
    b.emit(Insn::new(DW, 0, 8, 56, 0));
    let bound = ahead(&mut b, JNE_K, 0, 0, 0);
    equal64(&mut b, 8, 8, 0, Label::Malformed);
    saved(&mut b, 1, FILE);
    b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
    b.emit(Insn::new(ATOMIC_ADD_DW, 8, 1, 56, CMPXCHG));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    for (slot, off) in [(TFILE, 64), (TUN, 72), (DEV, 80)] {
        saved(&mut b, 0, slot);
        b.emit(Insn::new(SDW, 8, 0, off, 0));
    }
    b.emit(Insn::new(LDX_W, 0, 10, COUNT, 0));
    b.emit(Insn::new(STX_W, 8, 0, 140, 0));
    patch(&mut b, bound);
    for (slot, off) in [(FILE, 56), (TFILE, 64), (TUN, 72), (DEV, 80)] {
        saved(&mut b, 0, slot);
        b.emit(Insn::new(DW, 1, 8, off, 0));
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    }
    saved(&mut b, 6, TUN);
    read(&mut b, 6, o.tun_filter_prog, 8, TEMP, Label::Malformed);
    saved(&mut b, 6, TEMP);
    b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Malformed);
    read(&mut b, 6, o.tun_prog_program, 8, TEMP, Label::Malformed);
    saved(&mut b, 6, TEMP);
    b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Malformed);
    read(&mut b, 6, o.bpf_prog_aux, 8, TEMP, Label::Malformed);
    saved(&mut b, 6, TEMP);
    b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Malformed);
    read(&mut b, 6, o.bpf_prog_aux_id, 4, TEMP, Label::Malformed);
    check(
        &mut b,
        LDX_W,
        10,
        TEMP,
        o.filter_id as i32,
        Label::Malformed,
    );
    saved(&mut b, 6, ITER);
    read(&mut b, 6, o.iter_type, 1, TEMP, Label::Malformed);
    check(
        &mut b,
        LDX_B,
        10,
        TEMP,
        o.iter_ubuf as i32,
        Label::Malformed,
    );
    read(&mut b, 6, o.iter_source, 1, TEMP, Label::Malformed);
    check(&mut b, LDX_B, 10, TEMP, 0, Label::Malformed);
    read(&mut b, 6, o.iter_nofault, 1, TEMP, Label::Malformed);
    check(&mut b, LDX_B, 10, TEMP, 0, Label::Malformed);
    read(&mut b, 6, o.iter_count, 8, TEMP, Label::Malformed);
    saved(&mut b, 0, TEMP);
    b.emit(Insn::new(DW, 1, 7, 56, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.jump(Insn::new(0xb5, 0, 0, 0, 10), Label::Malformed);
    b.jump(Insn::new(JGT_K, 0, 0, 0, i32::MAX), Label::Malformed);
    b.emit(Insn::new(SDW, 7, 0, 128, 0));
    b.emit(Insn::new(ST64, 7, 0, 232, TUN_WITNESS_OUTER_ENTRY as i32));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    b.label(Label::Malformed);
    window_fault(&mut b);
    end(&mut b, false);
    b.finish()
}
fn active(
    b: &mut Builder,
    c: &TunProgramConfig,
    o: &TunKernelOffsets,
    m: TunMaps,
    witness: Option<u64>,
) {
    trace_window(b, c, m);
    equal64(b, 7, 8, TUN_PHASE_ENTERED, Label::Drop);
    if let Some(witness) = witness {
        equal64(b, 7, 232, witness, Label::Malformed);
    }
    task(b, o, false);
}
fn copy_enter(c: &TunProgramConfig, o: &TunKernelOffsets, m: TunMaps) -> io::Result<Program> {
    let mut b = Builder::new();
    active(&mut b, c, o, m, Some(TUN_WITNESS_OUTER_ENTRY));
    arg(&mut b, 0, 6, Label::Malformed);
    b.emit(Insn::new(SDW, 10, 6, SKB, 0));
    arg(&mut b, 1, 0, Label::Malformed);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    arg(&mut b, 2, 6, Label::Malformed);
    b.emit(Insn::new(SDW, 10, 6, ITER, 0));
    b.emit(Insn::new(DW, 0, 7, 120, 0));
    b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Malformed);
    arg(&mut b, 3, 0, Label::Malformed);
    b.emit(Insn::new(STX_W, 7, 0, 212, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    b.jump(Insn::new(JGT_K, 0, 0, 0, i32::MAX - 10), Label::Malformed);
    saved(&mut b, 6, SKB);
    read(&mut b, 6, o.skb_len, 4, TEMP, Label::Malformed);
    b.emit(Insn::new(LDX_W, 0, 10, TEMP, 0));
    b.emit(Insn::new(LDX_W, 1, 7, 212, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    read(&mut b, 6, o.skb_cb, 20, REC, Label::Malformed);
    check(
        &mut b,
        LDX_W,
        10,
        REC,
        TUN_STAMP_MAGIC as i32,
        Label::Malformed,
    );
    check(
        &mut b,
        LDX_W,
        10,
        REC + 16,
        c.attachment as u32 as i32,
        Label::Malformed,
    );
    b.emit(Insn::new(LDX_W, 0, 10, REC + 12, 0));
    b.jump(
        Insn::new(JGE_K, 0, 0, 0, TUN_PACKET_CELLS as i32),
        Label::Malformed,
    );
    b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
    b.emit(Insn::new(STX_W, 7, 0, 192, 0));
    lookup(&mut b, m.packets);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    b.emit(Insn::new(LDX_W, 0, 10, REC + 8, 0));
    b.emit(Insn::new(LSH_K, 0, 0, 0, 32));
    b.emit(Insn::new(LDX_W, 1, 10, REC + 4, 0));
    b.emit(Insn::new(0x4f, 0, 1, 0, 0));
    b.emit(Insn::new(DW, 1, 6, 8, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    equal64(&mut b, 6, 16, c.owner_epoch, Label::Malformed);
    equal64(&mut b, 6, 48, c.attachment, Label::Malformed);
    equal64(&mut b, 6, 56, c.netns_cookie, Label::Malformed);
    check(&mut b, LDX_W, 6, 64, c.ifindex as i32, Label::Malformed);
    b.emit(Insn::new(DW, 0, 6, 24, 0));
    saved(&mut b, 1, SKB);
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(LDX_W, 0, 6, 68, 0));
    b.emit(Insn::new(LDX_W, 1, 7, 212, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    cas(
        &mut b,
        6,
        0,
        TUN_PACKET_LIVE,
        TUN_PACKET_CLAIMED,
        Label::Malformed,
    );
    b.emit(Insn::new(DW, 0, 7, 48, 0));
    b.emit(Insn::new(SDW, 6, 0, 168, 0));
    copy_words(&mut b, 7, 160, 6, 8, 8);
    copy_words(&mut b, 7, 168, 6, 24, 24);
    b.emit(Insn::new(LDX_W, 0, 6, 68, 0));
    b.emit(Insn::new(STX_W, 7, 0, 196, 0));
    copy_words(&mut b, 7, 200, 6, 72, 8);
    copy_words(&mut b, 7, 248, 6, 80, 80);
    saved(&mut b, 6, ITER);
    read(&mut b, 6, o.iter_count, 8, TEMP, Label::Malformed);
    saved(&mut b, 0, TEMP);
    b.emit(Insn::new(SDW, 7, 0, 136, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 10));
    b.emit(Insn::new(DW, 1, 7, 128, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(ST_W, 7, 0, 208, 0));
    b.emit(Insn::new(
        ST64,
        7,
        0,
        232,
        (TUN_WITNESS_OUTER_ENTRY | TUN_WITNESS_COPY_ENTRY) as i32,
    ));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    b.label(Label::Malformed);
    window_fault(&mut b);
    end(&mut b, false);
    b.finish()
}
fn copy_exit(c: &TunProgramConfig, o: &TunKernelOffsets, m: TunMaps) -> io::Result<Program> {
    let mut b = Builder::new();
    active(&mut b, c, o, m, Some(3));
    arg(&mut b, 0, 6, Label::Malformed);
    b.emit(Insn::new(DW, 0, 7, 168, 0));
    b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Malformed);
    arg(&mut b, 1, 0, Label::Malformed);
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    arg(&mut b, 2, 6, Label::Malformed);
    b.emit(Insn::new(DW, 0, 7, 120, 0));
    b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Malformed);
    b.emit(Insn::new(SDW, 10, 6, ITER, 0));
    arg(&mut b, 3, 0, Label::Malformed);
    b.emit(Insn::new(LDX_W, 1, 7, 212, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    arg(&mut b, 4, 0, Label::Malformed);
    b.emit(Insn::new(LSH_K, 0, 0, 0, 32));
    b.emit(Insn::new(0xc7, 0, 0, 0, 32));
    b.emit(Insn::new(SDW, 7, 0, 216, 0));
    saved(&mut b, 6, ITER);
    read(&mut b, 6, o.iter_count, 8, TEMP, Label::Malformed);
    saved(&mut b, 0, TEMP);
    b.emit(Insn::new(SDW, 7, 0, 144, 0));
    b.emit(Insn::new(ST64, 7, 0, 232, 7));
    equal64(&mut b, 7, 216, 0, Label::Malformed);
    b.emit(Insn::new(DW, 0, 7, 144, 0));
    b.emit(Insn::new(DW, 1, 7, 136, 0));
    b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(SUB_X, 1, 0, 0, 0));
    b.emit(Insn::new(LDX_W, 0, 7, 212, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    b.label(Label::Malformed);
    window_fault(&mut b);
    end(&mut b, false);
    b.finish()
}
fn read_exit(c: &TunProgramConfig, o: &TunKernelOffsets, m: TunMaps) -> io::Result<Program> {
    let mut b = Builder::new();
    active(&mut b, c, o, m, None);
    arg(&mut b, 0, 6, Label::Malformed);
    b.emit(Insn::new(DW, 0, 7, 112, 0));
    b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Malformed);
    arg(&mut b, 1, 6, Label::Malformed);
    b.emit(Insn::new(DW, 0, 7, 120, 0));
    b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Malformed);
    b.emit(Insn::new(SDW, 10, 6, ITER, 0));
    arg(&mut b, 2, 0, Label::Malformed);
    b.emit(Insn::new(SDW, 7, 0, 224, 0));
    saved(&mut b, 6, ITER);
    read(&mut b, 6, o.iter_count, 8, TEMP, Label::Malformed);
    saved(&mut b, 0, TEMP);
    b.emit(Insn::new(SDW, 7, 0, 152, 0));
    equal64(&mut b, 7, 16, 0, Label::Malformed);
    b.emit(Insn::new(DW, 0, 7, 224, 0));
    let eagain = ahead(&mut b, JEQ_K, 0, 0, -libc::EAGAIN);
    let eintr = ahead(&mut b, JEQ_K, 0, 0, -libc::EINTR);
    equal64(&mut b, 7, 232, 7, Label::Malformed);
    equal64(&mut b, 7, 216, 0, Label::Malformed);
    b.emit(Insn::new(LDX_W, 1, 7, 196, 0));
    b.emit(Insn::new(ADD_K, 1, 0, 0, 10));
    b.emit(Insn::new(DW, 0, 7, 224, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(DW, 2, 7, 56, 0));
    b.jump(Insn::new(0x3d, 0, 2, 0, 0), Label::Malformed);
    b.emit(Insn::new(DW, 1, 7, 128, 0));
    b.emit(Insn::new(DW, 2, 7, 152, 0));
    b.jump(Insn::new(JGT_X, 2, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(SUB_X, 1, 2, 0, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    b.emit(Insn::new(LDX_W, 0, 7, 192, 0));
    b.jump(
        Insn::new(JGE_K, 0, 0, 0, TUN_PACKET_CELLS as i32),
        Label::Malformed,
    );
    b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
    lookup(&mut b, m.packets);
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Malformed);
    b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
    for (cell, win) in [(8, 160), (24, 168), (168, 48)] {
        b.emit(Insn::new(DW, 0, 6, cell, 0));
        b.emit(Insn::new(DW, 1, 7, win, 0));
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    }
    cas(
        &mut b,
        6,
        0,
        TUN_PACKET_CLAIMED,
        TUN_PACKET_RETIRED,
        Label::Malformed,
    );
    cas(
        &mut b,
        6,
        0,
        TUN_PACKET_RETIRED,
        TUN_PACKET_FREE,
        Label::Malformed,
    );
    b.map_fd(m.free);
    stack(&mut b, 2, KEY);
    b.emit(Insn::new(MOV_K, 3, 0, 0, 0));
    b.emit(Insn::new(CALL, 0, 0, 0, 87));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Malformed);
    saved(&mut b, 8, OWNER);
    b.emit(Insn::new(MOV_K, 1, 0, 0, 1));
    b.emit(Insn::new(ATOMIC_ADD_DW, 8, 1, 160, 0));
    b.emit(Insn::new(
        ST_W,
        7,
        0,
        240,
        TUN_STATUS_COMPLETE_RECORD as i32,
    ));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Selected);
    patch(&mut b, eagain);
    patch(&mut b, eintr);
    equal64(&mut b, 7, 232, TUN_WITNESS_OUTER_ENTRY, Label::Malformed);
    b.emit(Insn::new(DW, 0, 7, 128, 0));
    b.emit(Insn::new(DW, 1, 7, 152, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
    equal64(&mut b, 7, 160, 0, Label::Malformed);
    b.emit(Insn::new(ST_W, 7, 0, 240, TUN_STATUS_NO_RECORD as i32));
    b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Selected);
    b.label(Label::Malformed);
    window_fault(&mut b);
    b.label(Label::Selected);
    b.emit(Insn::new(DW, 0, 7, 232, 0));
    b.emit(Insn::new(OR_K, 0, 0, 0, TUN_WITNESS_OUTER_EXIT as i32));
    b.emit(Insn::new(SDW, 7, 0, 232, 0));
    cas(
        &mut b,
        7,
        8,
        TUN_PHASE_ENTERED,
        TUN_PHASE_COMPLETE,
        Label::Drop,
    );
    end(&mut b, false);
    b.finish()
}
fn close_hook(
    c: &TunProgramConfig,
    o: &TunKernelOffsets,
    m: TunMaps,
    exit: bool,
) -> io::Result<Program> {
    let mut b = Builder::new();
    b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
    owner(&mut b, c, m, false, Label::Drop);
    equal64(&mut b, 8, 8, 0, Label::Drop);
    arg(&mut b, 1, 6, Label::Drop);
    b.emit(Insn::new(SDW, 10, 6, FILE, 0));
    b.emit(Insn::new(DW, 0, 8, 56, 0));
    b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
    b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Drop);
    if exit {
        equal64(&mut b, 8, 88, 1, Label::Drop);
        b.emit(Insn::new(DW, 0, 8, 104, 0));
        b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Drop);
        arg(&mut b, 2, 0, Label::Drop);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(CALL, 0, 0, 0, 35));
        b.emit(Insn::new(DW, 1, 8, 168, 0));
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
        zero_key(&mut b);
        lookup(&mut b, m.window);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 7, 0, 0, 0));
        b.emit(Insn::new(MOV_K, 0, 0, 0, TUN_PHASE_CLOSED as i32));
        b.emit(Insn::new(ATOMIC_ADD_DW, 7, 0, 8, 0xe1));
        cas(&mut b, 8, 96, 0, 1, Label::Drop);
    } else {
        read(&mut b, 6, o.file_private, 8, TFILE, Label::Drop);
        saved(&mut b, 6, TFILE);
        b.emit(Insn::new(DW, 0, 8, 64, 0));
        b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Drop);
        read(&mut b, 6, o.tfile_tun, 8, TUN, Label::Drop);
        saved(&mut b, 6, TUN);
        b.emit(Insn::new(DW, 0, 8, 72, 0));
        b.jump(Insn::new(JNE_X, 0, 6, 0, 0), Label::Drop);
        cas(&mut b, 8, 88, 0, 1, Label::Drop);
        for (slot, off) in [(FILE, 104), (TFILE, 112), (TUN, 120)] {
            saved(&mut b, 0, slot);
            b.emit(Insn::new(SDW, 8, 0, off, 0));
        }
        b.emit(Insn::new(CALL, 0, 0, 0, 35));
        b.emit(Insn::new(SDW, 8, 0, 168, 0));
    }
    end(&mut b, false);
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_never_references_lock_or_selection_counter_maps() {
        let c = TunProgramConfig {
            owner_epoch: 1,
            attachment: 2,
            netns_cookie: 3,
            ifindex: 4,
            bypass_mark: 8,
            owner_tgid: 10,
        };
        let o = TunKernelOffsets {
            cast: 1,
            ..Default::default()
        };
        let m = TunMaps {
            sockets: 11,
            locks: 12,
            gate: 13,
            sequence: 14,
            packets: 15,
            free: 16,
            owner: 17,
            window: 18,
        };
        let p = filter(&c, &o, m).unwrap();
        assert!(p.len <= 4096);
        for insn in &p.insns[..p.len] {
            if insn.code == LD_MAP && insn.regs >> 4 == 1 {
                assert!(![m.locks, m.sequence].contains(&insn.imm));
            }
            if insn.code == CALL && insn.regs >> 4 == 0 {
                assert!(![93, 94].contains(&insn.imm));
            }
        }
        for p in [
            selector(&c, &o, m).unwrap(),
            read_enter(&c, &o, m).unwrap(),
            copy_enter(&c, &o, m).unwrap(),
            copy_exit(&c, &o, m).unwrap(),
            read_exit(&c, &o, m).unwrap(),
            close_hook(&c, &o, m, false).unwrap(),
            close_hook(&c, &o, m, true).unwrap(),
        ] {
            assert!(p.len <= 4096);
            let mut pending = vec![(0usize, false)];
            let mut seen = vec![[false; 2]; p.len];
            while let Some((pc, mut locked)) = pending.pop() {
                assert!(pc < p.len);
                if seen[pc][usize::from(locked)] {
                    continue;
                }
                seen[pc][usize::from(locked)] = true;
                let insn = p.insns[pc];
                if insn.code == CALL {
                    match insn.imm {
                        93 => {
                            assert!(!locked);
                            locked = true;
                        }
                        94 => {
                            assert!(locked);
                            locked = false;
                        }
                        _ => assert!(!locked, "helper called while bank locked"),
                    }
                }
                if insn.code == EXIT {
                    assert!(!locked);
                    continue;
                }
                if matches!(insn.code & 7, 5 | 6) && insn.code != CALL {
                    pending.push(((pc as isize + 1 + insn.off as isize) as usize, locked));
                    if insn.code == JA {
                        continue;
                    }
                }
                pending.push((pc + if insn.code == LD_MAP { 2 } else { 1 }, locked));
            }
        }
    }
}
