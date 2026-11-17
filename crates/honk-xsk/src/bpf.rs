use std::io;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aya_obj::btf::{Btf, BtfKind};
use aya_obj::generated::bpf_insn;

use honk_ebpf_common::xdp::{NativeKey, NativeRoot};

use crate::topology::{NativeUpdateOutcome, NativeXdpUpdates};
use crate::{Capture, Protocol};
mod general;
#[cfg(feature = "host")]
mod host;
mod native;
#[cfg(feature = "host")]
mod source;
#[cfg(feature = "host")]
mod tun;

#[cfg(feature = "host")]
pub use host::{HostPrograms, HostTcxAttachment};
#[cfg(feature = "host")]
pub use source::native::{
    HostNativeCandidate, HostNativeConfig, HostNativeHook, HostNativeLayout,
    HostNativeLayoutAdmission, HostNativeMaps, HostNativePrograms,
};
#[cfg(feature = "host")]
pub use source::{HostSourceConfig, HostSourcePrograms};
#[cfg(feature = "host")]
pub use tun::{TunKernelOffsets, TunMaps, TunProgramConfig, TunPrograms, TunTraceTarget};

pub use native::captured::{
    CapturedGateIdentity, CapturedLayout, CapturedProgramConfig, CapturedPrograms,
    CapturedResource, CapturedResourceState, CapturedTarget,
};
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_PROG_LOAD: u32 = 5;
const BPF_OBJ_PIN: u32 = 6;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_PROG_QUERY: u32 = 16;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_LINK_CREATE: u32 = 28;
const BPF_LINK_UPDATE: u32 = 29;
const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_XDP: u32 = 37;
const BPF_LINK_TYPE_XDP: u32 = 6;
const BPF_F_REPLACE: u32 = 4;
const BPF_F_PATH_FD: u32 = 1 << 14;
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;
const XDP_FLAGS_REPLACE: u32 = 1 << 4;
const XDP_FLAGS_DRV_MODE: u32 = 4;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const MAX_QUEUES: u32 = 256;
const MAX_PROGRAM_INSNS: usize = 1_000_000;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
const BPF_TCX_INGRESS: u32 = 46;
const BPF_TCX_EGRESS: u32 = 47;
const TCX_QUERY_CAPACITY: usize = 64;
pub const NATIVE_DISPATCH_SLOTS: u32 = 2;

#[repr(C)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
}

#[repr(C)]
struct MapElemAttr {
    map_fd: u32,
    reserved: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_fd: u32,
    core_relo_cnt: u32,
    fd_array: u64,
}

#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
}

#[repr(C)]
struct LinkUpdateAttr {
    link_fd: u32,
    new_prog_fd: u32,
    flags: u32,
    old_prog_fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TcxAttachAttr {
    target_ifindex: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
    relative_fd: u32,
    expected_revision: u64,
}

#[repr(C)]
#[derive(Default)]
struct TcxQueryAttr {
    target_ifindex: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    count: u32,
    padding: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

#[derive(Clone, Debug)]
struct TcxChain {
    programs: [u32; TCX_QUERY_CAPACITY],
    links: [u32; TCX_QUERY_CAPACITY],
    count: usize,
    revision: u64,
}

fn query_tcx_with(
    ifindex: u32,
    direction: u32,
    query: impl FnOnce(u32, &mut TcxQueryAttr) -> io::Result<()>,
) -> io::Result<TcxChain> {
    let mut chain = TcxChain {
        programs: [0; TCX_QUERY_CAPACITY],
        links: [u32::MAX; TCX_QUERY_CAPACITY],
        count: 0,
        revision: 0,
    };
    let mut program_flags = [u32::MAX; TCX_QUERY_CAPACITY];
    let mut link_flags = [u32::MAX; TCX_QUERY_CAPACITY];
    let mut attr = TcxQueryAttr {
        target_ifindex: ifindex,
        attach_type: direction,
        prog_ids: chain.programs.as_mut_ptr() as u64,
        link_ids: chain.links.as_mut_ptr() as u64,
        prog_attach_flags: program_flags.as_mut_ptr() as u64,
        link_attach_flags: link_flags.as_mut_ptr() as u64,
        count: TCX_QUERY_CAPACITY as u32,
        ..TcxQueryAttr::default()
    };
    query(BPF_PROG_QUERY, &mut attr)?;
    let count = attr.count as usize;
    if count > TCX_QUERY_CAPACITY || attr.revision == 0 || attr.attach_flags != 0 {
        return Err(invalid_data("incomplete or invalid Native TCX query"));
    }
    for index in 0..count {
        if chain.programs[index] == 0
            || chain.links[index] == u32::MAX
            || program_flags[index] != 0
            || link_flags[index] != 0
        {
            return Err(invalid_data("incomplete or flagged Native TCX entry"));
        }
    }
    chain.count = count;
    chain.revision = attr.revision;
    Ok(chain)
}

fn query_tcx(ifindex: u32, direction: u32) -> io::Result<TcxChain> {
    query_tcx_with(ifindex, direction, |command, attr| {
        bpf(command, attr).map(|_| ())
    })
}

fn require_empty_tcx(chain: &TcxChain) -> io::Result<()> {
    if chain.count != 0 || chain.revision == 0 {
        return Err(invalid_data("foreign or stale Native TCX attachment"));
    }
    Ok(())
}

fn require_gate_tcx(ingress: &TcxChain, egress: &TcxChain, program: u32) -> io::Result<()> {
    if program == 0
        || ingress.count != 1
        || ingress.programs[0] != program
        || ingress.links[0] != 0
        || ingress.revision == 0
    {
        return Err(invalid_data(
            "Native gate is not the exact non-link ingress singleton",
        ));
    }
    require_empty_tcx(egress)
}

#[repr(C)]
#[derive(Default)]
struct ProgInfo {
    kind: u32,
    id: u32,
}

#[repr(C)]
#[derive(Default)]
struct LinkInfo {
    kind: u32,
    id: u32,
    prog_id: u32,
    reserved: u32,
    ifindex: u32,
    tail_padding: u32,
}

fn bpf<T>(command: u32, attr: &mut T) -> io::Result<RawFd> {
    // SAFETY: callers supply the command's repr(C) UAPI layout and keep every
    // referenced buffer alive and appropriately readable/writable through this call.
    let result = unsafe { libc::syscall(libc::SYS_bpf, command, attr as *mut T, size_of::<T>()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        i32::try_from(result).map_err(|_| io::Error::other("BPF syscall result exceeds RawFd"))
    }
}

fn bpf_fd<T>(command: u32, attr: &mut T) -> io::Result<OwnedFd> {
    let fd = bpf(command, attr)?;
    // SAFETY: these commands return a newly owned descriptor on success.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn object_info<T>(fd: BorrowedFd<'_>, info: &mut T) -> io::Result<()> {
    let mut attr = InfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: size_of::<T>() as u32,
        info: info as *mut T as u64,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;
    if (attr.info_len as usize) < size_of::<T>() {
        return Err(invalid_data("short BPF object information"));
    }
    Ok(())
}

fn object_name(name: &[u8]) -> [u8; 16] {
    let mut result = [0; 16];
    assert!(name.len() < result.len());
    result[..name.len()].copy_from_slice(name);
    result
}

fn create_map(kind: u32, value_size: u32, entries: u32, name: &[u8]) -> io::Result<OwnedFd> {
    bpf_fd(
        BPF_MAP_CREATE,
        &mut MapCreateAttr {
            map_type: kind,
            key_size: 4,
            value_size,
            max_entries: entries,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: object_name(name),
        },
    )
}

fn map_attr(fd: BorrowedFd<'_>, key: &u32, value: u64) -> MapElemAttr {
    MapElemAttr {
        map_fd: fd.as_raw_fd() as u32,
        reserved: 0,
        key: key as *const u32 as u64,
        value,
        flags: 0,
    }
}
fn map_value<T: Copy + Default>(fd: BorrowedFd<'_>, key: &u32) -> io::Result<T> {
    let mut value = T::default();
    bpf(
        BPF_MAP_LOOKUP_ELEM,
        &mut map_attr(fd, key, &mut value as *mut T as u64),
    )?;
    Ok(value)
}

/// Inputs needed to load one emitted canonical routing program.
pub struct NativeProgramConfig<'a> {
    pub bytecode: &'a [bpf_insn],
    pub root: RawFd,
    pub claims: RawFd,
    pub scratch: RawFd,
    pub closed_counters: RawFd,
    pub hook_ids: [u64; 2],
    pub epoch: u64,
    pub scope: u64,
    pub expires_boottime_ns: u64,
    pub redirect_limit: u32,
    pub captured: Option<&'a CapturedProgramConfig<'a>>,
    pub reply_block_rules: &'a [u32],
    pub preparation_memory_bytes: usize,
}
struct NativeDispatch {
    map: OwnedFd,
    capture: crate::capture::GeneralCapture,
    broadcasts: Vec<Ipv4Addr>,
    vlan_kfunc: Option<u32>,
    attachment: Mutex<Option<PersistentAttachment>>,
}

pub struct NativeTarget {
    counters: OwnedFd,
    xsks: OwnedFd,
    dispatch: OwnedFd,
    query_program: Arc<Mutex<Option<OwnedFd>>>,
    capture: crate::capture::GeneralCapture,
    broadcasts: Vec<Ipv4Addr>,
    queues: u32,
    vlan_kfunc: Option<u32>,
    attachment: PersistentAttachment,
    recording: Mutex<Option<(u32, [u64; 2])>>,
}

pub struct NativePrograms {
    xdp_program: OwnedFd,
    xdp_id: u32,
    tc_program: OwnedFd,
    tc_id: u32,
    _kfunc_btf: Option<OwnedFd>,
    _root: RawFd,
    _claims: RawFd,
    _scratch: RawFd,
    closed_counters: OwnedFd,
    closed_counters_id: u32,
    hook_ids: [u64; 2],
    epoch: u64,
    scope: u64,
    expires_boottime_ns: u64,
    captured: Option<native::captured::CanonicalGate>,
}

pub struct NativeTcxAttachment {
    program: OwnedFd,
    root: OwnedFd,
    ifindex: u32,
    program_id: u32,
    authority: honk_ebpf_common::xdp::CaptureAuthority,
    pin: PathBuf,
    captured: Mutex<Option<CapturedPrograms>>,
}

pub struct Programs {
    counters: OwnedFd,
    xsks: OwnedFd,
    discover: OwnedFd,
    data: OwnedFd,
    native_dispatch: Option<NativeDispatch>,
    discover_id: u32,
    data_id: u32,
    queues: u32,
}

impl Programs {
    pub fn load_general(
        capture: &crate::capture::GeneralCapture,
        queues: u32,
        ipv4_broadcasts: &[Ipv4Addr],
    ) -> io::Result<Self> {
        Self::load_general_inner(capture, queues, ipv4_broadcasts, false)
    }

    fn load_general_inner(
        capture: &crate::capture::GeneralCapture,
        queues: u32,
        ipv4_broadcasts: &[Ipv4Addr],
        native: bool,
    ) -> io::Result<Self> {
        validate_queues(queues)?;
        if !capture.authority.is_valid()
            || capture.bypass_mark == 0
            || capture.bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XDP capture authority or bypass mark",
            ));
        }
        let counters = create_map(2, 8, queues + 4, b"honk_xdp_count")?;
        let xsks = create_map(17, 4, queues, b"honk_xdp_xsks")?;
        let mut native_dispatch = native
            .then(|| {
                create_map(
                    BPF_MAP_TYPE_PROG_ARRAY,
                    4,
                    NATIVE_DISPATCH_SLOTS,
                    b"honk_nat_tc",
                )
                .map(|map| NativeDispatch {
                    map,
                    capture: capture.clone(),
                    broadcasts: ipv4_broadcasts.to_vec(),
                    vlan_kfunc: None,
                    attachment: Mutex::new(None),
                })
            })
            .transpose()?;
        let mut log = vec![0; 1 << 20];
        let vlan_kfunc = if capture.vlan_metadata {
            Some(
                Btf::from_sys_fs()
                    .and_then(|btf| {
                        btf.id_by_type_name_kind("bpf_xdp_metadata_rx_vlan_tag", BtfKind::Func)
                    })
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::Unsupported,
                            format!("RX VLAN kfunc BTF: {error}"),
                        )
                    })?,
            )
        } else {
            None
        };
        if let Some(dispatch) = &mut native_dispatch {
            dispatch.vlan_kfunc = vlan_kfunc;
        }
        let (discover, discover_id) = load_program(
            &general::build(
                capture,
                ipv4_broadcasts,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                false,
                vlan_kfunc,
            )?,
            b"honk_xdp_guard",
            &mut log,
        )?;
        let (data, data_id) = load_program(
            &general::build(
                capture,
                ipv4_broadcasts,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                !native,
                vlan_kfunc,
            )?,
            b"honk_xdp_data",
            &mut log,
        )?;
        Ok(Self {
            counters,
            xsks,
            discover,
            data,
            native_dispatch,
            discover_id,
            data_id,
            queues,
        })
    }

    pub fn load_general_native(
        capture: &crate::capture::GeneralCapture,
        queues: u32,
        ipv4_broadcasts: &[Ipv4Addr],
    ) -> io::Result<Self> {
        Self::load_general_inner(capture, queues, ipv4_broadcasts, true)
    }

    pub fn native_dispatch_fd(&self) -> Option<BorrowedFd<'_>> {
        self.native_dispatch
            .as_ref()
            .map(|dispatch| dispatch.map.as_fd())
    }

    pub fn native_memory_bytes(&self) -> io::Result<usize> {
        let dispatch = self.native_dispatch.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "native dispatch is not enabled",
            )
        })?;
        fd_memlock(dispatch.map.as_fd())?
            .try_into()
            .map_err(|_| io::Error::other("native dispatch memlock exceeds usize"))
    }
    pub fn native_preparation_memory_bytes() -> io::Result<usize> {
        native::preparation_memory_bytes()
    }

    pub fn native_target(
        &self,
        capture: &crate::capture::GeneralCapture,
        ipv4_broadcasts: &[Ipv4Addr],
        attachment: &PersistentAttachment,
    ) -> io::Result<Arc<NativeTarget>> {
        let dispatch = self.native_dispatch.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "native dispatch is not enabled",
            )
        })?;
        attachment.check_programs(self)?;
        if capture.authority != dispatch.capture.authority
            || capture.bypass_mark != dispatch.capture.bypass_mark
            || capture.vlan_metadata != dispatch.capture.vlan_metadata
            || ipv4_broadcasts != dispatch.broadcasts.as_slice()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Native target differs from its capture owner",
            ));
        }
        if attachment.ifindex != capture.authority.ifindex || attachment.native.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Native target requires its exact persistent XDP attachment",
            ));
        }
        attachment
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("Native attachment missing"))?
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?
            .require_gate_with(NativeTcxAttachment::check)?;
        if ipv4_broadcasts.len() > crate::topology::MAX_BROADCASTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many native broadcast destinations",
            ));
        }
        Ok(Arc::new(NativeTarget {
            counters: self.counters.try_clone()?,
            xsks: self.xsks.try_clone()?,
            dispatch: dispatch.map.try_clone()?,
            query_program: Arc::new(Mutex::new(None)),
            capture: capture.clone(),
            broadcasts: ipv4_broadcasts.to_vec(),
            queues: self.queues,
            vlan_kfunc: dispatch.vlan_kfunc,
            attachment: attachment.clone(),
            recording: Mutex::new(None),
        }))
    }

    pub fn attach_native_gate(
        &self,
        attachment: &PersistentAttachment,
        pin_root: &Path,
    ) -> io::Result<Arc<NativeTcxAttachment>> {
        attachment.check_programs(self)?;
        let dispatch = self
            .native_dispatch
            .as_ref()
            .ok_or_else(|| invalid_data("Native dispatch is not enabled"))?;
        let authority = dispatch.capture.authority;
        if !authority.is_valid()
            || authority.ifindex != attachment.ifindex
            || authority.namespace_cookie != current_namespace_cookie()?
        {
            return Err(invalid_data("Native gate capture authority mismatch"));
        }
        let registered = dispatch
            .attachment
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        let native = attachment
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("Native XDP attachment missing"))?;
        if !registered
            .as_ref()
            .and_then(|owner| owner.native.as_ref())
            .is_some_and(|owner| Arc::ptr_eq(owner, native))
        {
            return Err(invalid_data(
                "Native gate requires its exact attachment owner",
            ));
        }
        let mut state = native
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        state.require_resolved()?;
        if state.active || state.gate.is_some() || state.retired.is_some() {
            return Err(invalid_data(
                "Native gate already registered or XDP is active",
            ));
        }
        require_native(xdp_state(attachment.ifindex)?, state.guard_id)?;
        let root = private_bpffs(pin_root)?;
        if directory_identity(root.as_fd())? != directory_identity(state.root.as_fd())? {
            return Err(invalid_data(
                "Native gate pin directory differs from XDP owner",
            ));
        }
        let mut log = vec![0; 1 << 20];
        let gate = native::dispatch(
            &dispatch.capture,
            &dispatch.broadcasts,
            dispatch.map.as_raw_fd(),
        )?;
        let (program, program_id) = load_typed_program(
            &gate,
            b"honk_nat_gate",
            &mut log,
            BPF_PROG_TYPE_SCHED_CLS,
            BPF_TCX_INGRESS,
        )?;
        let owner = Arc::new(NativeTcxAttachment {
            program,
            root,
            ifindex: attachment.ifindex,
            program_id,
            authority,
            pin: pin_root.join("native-gate-prog"),
            captured: Mutex::new(None),
        });
        install_native_gate_with(
            owner,
            |owner| {
                pin_program(
                    owner.root.as_fd(),
                    c"native-gate-prog",
                    owner.program.as_fd(),
                )
            },
            |owner| {
                pinned_program_id(
                    owner.root.as_fd(),
                    c"native-gate-prog",
                    BPF_PROG_TYPE_SCHED_CLS,
                )
            },
            query_tcx,
            |command, attr| bpf(command, attr).map(|_| ()),
            |owner| state.register_gate(owner),
        )
    }
}

impl NativeTarget {
    pub fn prepare(&self, config: &NativeProgramConfig<'_>) -> io::Result<NativePrograms> {
        native::validate_recording_config(config)?;
        if config.bytecode.is_empty()
            || config.bytecode.len() > u32::MAX as usize
            || config.root < 0
            || config.claims < 0
            || config.scratch < 0
            || config.epoch == 0
            || config.scope == 0
            || config.redirect_limit == 0
            || config.redirect_limit > (1 << 28) - 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native program configuration",
            ));
        }
        native::captured::admit_config(self, config)?;
        let closed_counters = native::admit_closed_counters(config.closed_counters)?;
        native::admit_counter_generation(config.closed_counters, config.epoch)?;
        let mut recording = self
            .recording
            .lock()
            .map_err(|_| invalid_data("Native recording identity lock poisoned"))?;
        if recording.is_some_and(|identity| identity != (closed_counters, config.hook_ids)) {
            return Err(invalid_data(
                "Native replacement changes recording map or hook identities",
            ));
        }
        let mut log = vec![0; 1 << 20];
        let xdp_body = native::build(
            &self.capture,
            config,
            self.counters.as_raw_fd(),
            self.xsks.as_raw_fd(),
            self.queues,
            false,
        )?;
        let xdp = general::build_with_native(
            general::Input {
                capture: &self.capture,
                ipv4_broadcasts: &self.broadcasts,
            },
            self.queues,
            self.counters.as_raw_fd(),
            self.xsks.as_raw_fd(),
            self.vlan_kfunc,
            xdp_body,
        )?;
        let tc = native::build(
            &self.capture,
            config,
            self.counters.as_raw_fd(),
            self.xsks.as_raw_fd(),
            self.queues,
            true,
        )?;
        let (xdp_program, xdp_id) = load_program(&xdp, b"honk_nat_xdp", &mut log)?;
        let (tc_program, tc_id) = load_typed_program(
            &tc,
            b"honk_nat_eval",
            &mut log,
            BPF_PROG_TYPE_SCHED_CLS,
            BPF_TCX_INGRESS,
        )?;
        native::admit_counter_reference(xdp_program.as_fd(), closed_counters)?;
        native::admit_counter_reference(tc_program.as_fd(), closed_counters)?;
        *recording = Some((closed_counters, config.hook_ids));
        let kfunc_btf = tc.kfunc_btf.as_ref().map(OwnedFd::try_clone).transpose()?;
        let captured = config
            .captured
            .map(|captured| native::captured::prepare_gate(self, config, captured, &mut log))
            .transpose()?;
        Ok(NativePrograms {
            xdp_program,
            xdp_id,
            tc_program,
            tc_id,
            _kfunc_btf: kfunc_btf,
            _root: config.root,
            _claims: config.claims,
            _scratch: config.scratch,
            closed_counters: unsafe { BorrowedFd::borrow_raw(config.closed_counters) }
                .try_clone_to_owned()?,
            closed_counters_id: closed_counters,
            hook_ids: config.hook_ids,
            epoch: config.epoch,
            scope: config.scope,
            expires_boottime_ns: config.expires_boottime_ns,
            captured,
        })
    }

    pub fn dispatch_fd(&self) -> BorrowedFd<'_> {
        self.dispatch.as_fd()
    }

    pub fn counters_fd(&self) -> BorrowedFd<'_> {
        self.counters.as_fd()
    }

    pub fn xsks_fd(&self) -> BorrowedFd<'_> {
        self.xsks.as_fd()
    }

    pub fn memory_bytes(&self) -> io::Result<usize> {
        fd_memlock(self.dispatch.as_fd())?
            .try_into()
            .map_err(|_| io::Error::other("native dispatch memlock exceeds usize"))
    }

    pub fn queues(&self) -> u32 {
        self.queues
    }

    pub fn capture(&self) -> &crate::capture::GeneralCapture {
        &self.capture
    }

    pub fn broadcasts(&self) -> &[Ipv4Addr] {
        &self.broadcasts
    }
    pub fn preparation_memory_bytes(&self) -> io::Result<usize> {
        native::preparation_memory_bytes()
    }
    pub fn kernel_owned(&self, key: &NativeKey) -> io::Result<bool> {
        if !key.is_valid()
            || key.namespace_cookie != self.capture.authority.namespace_cookie
            || key.domain != 0
            || key.direction != 0
            || key.zone != 0
            || key.zone_state != 2
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Transit Native query key",
            ));
        }
        let guard = self
            .query_program
            .lock()
            .map_err(|_| io::Error::other("native query program lock poisoned"))?;
        let program = guard.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "native TC program is not published",
            )
        })?;
        native::kernel_owned(program.as_fd(), key)
    }

    /// Called only after the publisher's second reader grace.
    pub fn finish_publication(&self) -> io::Result<()> {
        self.attachment.finish_native_publication()?;
        native::captured::finish_publication(self)
    }

    pub fn recording_identity(&self) -> io::Result<(u64, u32)> {
        let authority = self.capture.authority;
        if !authority.is_valid() || authority.ifindex != self.attachment.ifindex {
            return Err(invalid_data(
                "Native recording attachment authority mismatch",
            ));
        }
        Ok((authority.namespace_cookie, authority.ifindex))
    }

    pub fn bind_native_xdp_updates(&self, updates: NativeXdpUpdates) -> io::Result<()> {
        let mut native = self
            .attachment
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("Native XDP attachment missing"))?
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        native.require_resolved()?;
        if native.updates.is_some() || !native.active {
            return Err(invalid_data(
                "Native watch requires one active unbound attachment",
            ));
        }
        native.require_gate_with(NativeTcxAttachment::check)?;
        updates.lock().check()?;
        require_native(xdp_state(self.attachment.ifindex)?, native.data_id)?;
        updates.lock().check()?;
        native.updates = Some(updates);
        Ok(())
    }

    /// Only candidate slot one reaches accounting; the dispatcher and XDP guard do not.
    /// The owner must join readers with its grace after this returns successfully.
    pub fn withdraw_recording_hooks(&self) -> io::Result<()> {
        let mut native = self
            .attachment
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("Native XDP attachment missing"))?
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        withdraw_recording_hooks_with(
            || native.guard(self.attachment.ifindex),
            || {
                let key = 1u32;
                match bpf(
                    BPF_MAP_DELETE_ELEM,
                    &mut map_attr(self.dispatch.as_fd(), &key, 0),
                ) {
                    Ok(_) => Ok(()),
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                    Err(error) => Err(error),
                }
            },
            || {
                self.query_program
                    .lock()
                    .map_err(|_| invalid_data("Native query program lock poisoned"))
                    .map(|mut owner| *owner = None)
            },
        )
    }
}

impl NativePrograms {
    pub fn publish(&self, target: &NativeTarget) -> io::Result<()> {
        if self.epoch == 0 || self.scope == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native program has no publication identity",
            ));
        }
        if native::admit_closed_counters(self.closed_counters.as_raw_fd())?
            != self.closed_counters_id
            || *target
                .recording
                .lock()
                .map_err(|_| invalid_data("Native recording identity lock poisoned"))?
                != Some((self.closed_counters_id, self.hook_ids))
        {
            return Err(invalid_data(
                "Native publication recording identity mismatch",
            ));
        }
        let root_fd = unsafe { BorrowedFd::borrow_raw(self._root) };
        let root: NativeRoot = map_value(root_fd, &0)?;
        if root.epoch != self.epoch || root.epoch == 0 || root.epoch & 1 != 0 || root.reserved != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native dispatch publication requires the matching closed root",
            ));
        }
        native::admit_counter_generation(self.closed_counters.as_raw_fd(), self.epoch)?;
        if let Some(gate) = &self.captured {
            gate.publish(target)?;
        }
        let query_program = self.tc_program.try_clone()?;
        target
            .attachment
            .publish_native(self.xdp_program.as_fd(), self.xdp_id)?;
        target
            .attachment
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("Native XDP attachment missing"))?
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?
            .publish_with(NativeTcxAttachment::check, |_| {
                let mut query_owner = target
                    .query_program
                    .lock()
                    .map_err(|_| invalid_data("Native query program lock poisoned"))?;
                let key = 1u32;
                let value = self.tc_program.as_raw_fd() as u32;
                bpf(
                    BPF_MAP_UPDATE_ELEM,
                    &mut map_attr(target.dispatch.as_fd(), &key, &value as *const u32 as u64),
                )?;
                *query_owner = Some(query_program);
                Ok(())
            })?;
        Ok(())
    }

    pub fn program_id(&self) -> u32 {
        self.xdp_id
    }

    pub fn tc_program_id(&self) -> u32 {
        self.tc_id
    }

    pub fn captured_gate(&self) -> Option<CapturedGateIdentity> {
        self.captured
            .as_ref()
            .map(native::captured::CanonicalGate::identity)
    }

    pub fn memory_bytes(&self) -> io::Result<usize> {
        let xdp = fd_memlock(self.xdp_program.as_fd())?;
        let tc = fd_memlock(self.tc_program.as_fd())?;
        let captured = self
            .captured
            .as_ref()
            .map_or(Ok(0), native::captured::CanonicalGate::memory_bytes)?;
        xdp.checked_add(tc)
            .and_then(|bytes| bytes.checked_add(captured))
            .ok_or_else(|| io::Error::other("native program memlock overflow"))
            .and_then(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| io::Error::other("native program memlock exceeds usize"))
            })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn scope(&self) -> u64 {
        self.scope
    }

    pub fn expires_boottime_ns(&self) -> u64 {
        self.expires_boottime_ns
    }

    pub fn root_fd(&self) -> RawFd {
        self._root
    }

    pub fn claims_fd(&self) -> RawFd {
        self._claims
    }

    pub fn scratch_fd(&self) -> RawFd {
        self._scratch
    }
}

impl NativeTcxAttachment {
    pub fn program_id(&self) -> u32 {
        self.program_id
    }

    pub fn check(&self) -> io::Result<()> {
        self.check_with(
            current_namespace_cookie()?,
            pinned_program_id(
                self.root.as_fd(),
                c"native-gate-prog",
                BPF_PROG_TYPE_SCHED_CLS,
            )?,
            &query_tcx(self.ifindex, BPF_TCX_INGRESS)?,
            &query_tcx(self.ifindex, BPF_TCX_EGRESS)?,
        )
    }

    fn check_with(
        &self,
        namespace: u64,
        pin_id: u32,
        ingress: &TcxChain,
        egress: &TcxChain,
    ) -> io::Result<()> {
        if !self.authority.is_valid()
            || self.authority.ifindex != self.ifindex
            || self.authority.namespace_cookie != namespace
            || pin_id != self.program_id
        {
            return Err(invalid_data(
                "Native gate namespace, device or program pin changed",
            ));
        }
        let captured = self
            .captured
            .lock()
            .map_err(|_| invalid_data("Native captured attachment lock poisoned"))?;
        match captured.as_ref() {
            Some(owner) => owner.check_target_chain(self, ingress, egress),
            None => require_gate_tcx(ingress, egress, self.program_id),
        }
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub fn pin_path(&self) -> &Path {
        &self.pin
    }

    pub fn memory_bytes(&self) -> io::Result<usize> {
        fd_memlock(self.program.as_fd())?
            .try_into()
            .map_err(|_| io::Error::other("native gate memlock exceeds usize"))
    }
}

fn current_namespace_cookie() -> io::Result<u64> {
    // SAFETY: socket creates a new owned descriptor without borrowed pointers.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is the newly owned socket above.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut cookie = 0u64;
    let mut length = size_of::<u64>() as libc::socklen_t;
    // SAFETY: cookie and length are writable buffers of the specified extent.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<u64>() || cookie == 0 {
        return Err(invalid_data("invalid Native namespace cookie"));
    }
    Ok(cookie)
}

fn directory_identity(fd: BorrowedFd<'_>) -> io::Result<(u64, u64)> {
    // SAFETY: stat has no invalid all-zero representation.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable and fstat only inspects the borrowed descriptor.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((stat.st_dev, stat.st_ino))
}

fn tcx_mutate_with(
    command: u32,
    program: BorrowedFd<'_>,
    ifindex: u32,
    revision: u64,
    duplicate: impl FnOnce(BorrowedFd<'_>) -> io::Result<OwnedFd>,
    mutate: impl FnOnce(u32, &mut TcxAttachAttr) -> io::Result<()>,
    readback: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if !matches!(command, BPF_PROG_ATTACH | BPF_PROG_DETACH) || revision == 0 {
        return Err(invalid_data("invalid exact Native TCX mutation"));
    }
    let retained = if command == BPF_PROG_DETACH && program.as_raw_fd() == 0 {
        Some(duplicate(program)?)
    } else {
        None
    };
    let fd = retained
        .as_ref()
        .map_or(program.as_raw_fd(), AsRawFd::as_raw_fd);
    if command == BPF_PROG_DETACH && fd <= 0 {
        return Err(invalid_data(
            "exact Native TCX detach requires a nonzero FD",
        ));
    }
    let mut attr = TcxAttachAttr {
        target_ifindex: ifindex,
        attach_bpf_fd: fd as u32,
        attach_type: BPF_TCX_INGRESS,
        expected_revision: revision,
        ..TcxAttachAttr::default()
    };
    mutate(command, &mut attr)?;
    let result = readback();
    drop(retained);
    result
}

fn duplicate_nonzero_fd(program: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: fcntl duplicates this live descriptor without consuming it.
    let fd = unsafe { libc::fcntl(program.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 1) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a newly owned descriptor at least one.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn install_native_gate_with(
    owner: Arc<NativeTcxAttachment>,
    pin: impl FnOnce(&NativeTcxAttachment) -> io::Result<()>,
    mut pin_id: impl FnMut(&NativeTcxAttachment) -> io::Result<u32>,
    mut query: impl FnMut(u32, u32) -> io::Result<TcxChain>,
    mutate: impl FnOnce(u32, &mut TcxAttachAttr) -> io::Result<()>,
    register: impl FnOnce(Arc<NativeTcxAttachment>) -> io::Result<()>,
) -> io::Result<Arc<NativeTcxAttachment>> {
    pin(&owner)?;
    if pin_id(&owner)? != owner.program_id {
        return Err(invalid_data(
            "Native gate program pin mismatch before attach",
        ));
    }
    let ingress = query(owner.ifindex, BPF_TCX_INGRESS)?;
    require_empty_tcx(&ingress)?;
    require_empty_tcx(&query(owner.ifindex, BPF_TCX_EGRESS)?)?;
    tcx_mutate_with(
        BPF_PROG_ATTACH,
        owner.program.as_fd(),
        owner.ifindex,
        ingress.revision,
        duplicate_nonzero_fd,
        mutate,
        || {
            let installed = query(owner.ifindex, BPF_TCX_INGRESS)?;
            require_gate_tcx(
                &installed,
                &query(owner.ifindex, BPF_TCX_EGRESS)?,
                owner.program_id,
            )?;
            if installed.revision <= ingress.revision || pin_id(&owner)? != owner.program_id {
                return Err(invalid_data(
                    "Native gate revision or pin readback mismatch",
                ));
            }
            Ok(())
        },
    )?;
    register(Arc::clone(&owner))?;
    Ok(owner)
}

#[derive(Debug)]
pub struct CaptureCounters {
    pub per_queue: Vec<u64>,
    pub fragments: u64,
    pub options: u64,
    pub malformed: u64,
}

impl Programs {
    pub fn load(capture: &Capture, queues: u32) -> io::Result<Self> {
        validate_queues(queues)?;
        let counters = create_map(2, 8, queues + 4, b"honk_x0_count")?;
        let xsks = create_map(17, 4, queues, b"honk_x0_xsks")?;
        let mut log = vec![0; 1 << 20];
        let (discover, discover_id) = load_program(
            &build_program(
                capture,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                false,
            )?,
            b"honk_x0_disc",
            &mut log,
        )?;
        let (data, data_id) = load_program(
            &build_program(
                capture,
                queues,
                counters.as_raw_fd(),
                xsks.as_raw_fd(),
                true,
            )?,
            b"honk_x0_data",
            &mut log,
        )?;
        Ok(Self {
            counters,
            xsks,
            discover,
            data,
            native_dispatch: None,
            discover_id,
            data_id,
            queues,
        })
    }

    pub fn discover_prog_id(&self) -> u32 {
        self.discover_id
    }

    pub fn data_prog_id(&self) -> u32 {
        self.native_dispatch
            .as_ref()
            .and_then(|dispatch| dispatch.attachment.lock().ok()?.as_ref().cloned())
            .and_then(|attachment| attachment.current_data_id().ok())
            .unwrap_or(self.data_id)
    }

    pub fn counters(&self) -> io::Result<CaptureCounters> {
        let mut per_queue = Vec::with_capacity(self.queues as usize);
        for queue in 0..self.queues {
            per_queue.push(self.counter(queue)?);
        }
        Ok(CaptureCounters {
            per_queue,
            fragments: self.counter(self.queues)?,
            options: self.counter(self.queues + 1)?,
            malformed: self.counter(self.queues + 2)?,
        })
    }

    /// Runtime metadata-preparation failures, not a preflight capability proof.
    /// Wire-only and legacy narrow-tuple programs reserve this slot but never increment it.
    pub fn metadata_failures(&self) -> io::Result<u64> {
        self.counter(self.queues + 3)
    }

    fn counter(&self, key: u32) -> io::Result<u64> {
        let mut value = 0u64;
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            &mut map_attr(self.counters.as_fd(), &key, &mut value as *mut u64 as u64),
        )?;
        Ok(value)
    }

    pub fn insert_xsk(&self, queue: u32, fd: BorrowedFd<'_>) -> io::Result<()> {
        self.check_queue(queue)?;
        let value = fd.as_raw_fd() as u32;
        bpf(
            BPF_MAP_UPDATE_ELEM,
            &mut map_attr(self.xsks.as_fd(), &queue, &value as *const u32 as u64),
        )?;
        Ok(())
    }

    pub fn delete_xsk(&self, queue: u32) -> io::Result<()> {
        self.check_queue(queue)?;
        match bpf(
            BPF_MAP_DELETE_ELEM,
            &mut map_attr(self.xsks.as_fd(), &queue, 0),
        ) {
            Ok(_) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn check_queue(&self, queue: u32) -> io::Result<()> {
        if queue >= self.queues {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XSK queue exceeds capture map",
            ))
        } else {
            Ok(())
        }
    }
}

fn validate_queues(queues: u32) -> io::Result<()> {
    if !(1..=MAX_QUEUES).contains(&queues) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RX queue count must be 1..=256",
        ));
    }
    Ok(())
}

fn load_program(program: &Program, name: &[u8], log: &mut [u8]) -> io::Result<(OwnedFd, u32)> {
    load_typed_program(program, name, log, BPF_PROG_TYPE_XDP, BPF_XDP)
}

fn load_typed_program(
    program: &Program,
    name: &[u8],
    log: &mut [u8],
    kind: u32,
    attach_type: u32,
) -> io::Result<(OwnedFd, u32)> {
    log.fill(0);
    let fd_array = [
        0u32,
        program
            .kfunc_btf
            .as_ref()
            .map_or(0, |fd| fd.as_raw_fd() as u32),
    ];
    let mut attr = ProgLoadAttr {
        prog_type: kind,
        insn_cnt: program.len as u32,
        insns: program.insns.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: program.flags,
        prog_name: object_name(name),
        prog_ifindex: program.ifindex,
        expected_attach_type: attach_type,
        prog_btf_fd: 0,
        func_info_rec_size: 0,
        func_info: 0,
        func_info_cnt: 0,
        line_info_rec_size: 0,
        line_info: 0,
        line_info_cnt: 0,
        attach_btf_id: 0,
        attach_prog_fd: 0,
        core_relo_cnt: 0,
        fd_array: if program.kfunc_btf.is_some() {
            fd_array.as_ptr() as u64
        } else {
            0
        },
    };
    let fd = bpf_fd(BPF_PROG_LOAD, &mut attr).map_err(|error| {
        let length = log.iter().position(|&byte| byte == 0).unwrap_or(log.len());
        io::Error::new(
            error.kind(),
            format!(
                "BPF_PROG_LOAD {}: {error}\n{}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(&log[..length]),
            ),
        )
    })?;
    let mut info = ProgInfo::default();
    object_info(fd.as_fd(), &mut info)?;
    if info.kind != kind || info.id == 0 {
        return Err(invalid_data("BPF program identity readback mismatch"));
    }
    Ok((fd, info.id))
}

fn fd_memlock(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let path = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
    let info = std::fs::read_to_string(path)?;
    let mut value = None;
    for line in info
        .lines()
        .filter_map(|line| line.strip_prefix("memlock:"))
    {
        if value.is_some() {
            return Err(invalid_data("BPF fdinfo has duplicate memlock fields"));
        }
        let parsed = line
            .trim()
            .parse::<u64>()
            .map_err(|_| invalid_data("BPF fdinfo has malformed memlock"))?;
        if parsed == 0 {
            return Err(invalid_data("BPF fdinfo has zero memlock"));
        }
        value = Some(parsed);
    }
    value.ok_or_else(|| invalid_data("BPF fdinfo has no memlock field"))
}

/// Persistent XDP custody with exclusively pinned guard/data programs.
/// The netdev retains driver-mode custody independently of creator FDs.
/// Drop never detaches; deliberate removal requires source-quiesced recovery.
#[derive(Clone)]
pub struct PersistentAttachment {
    ifindex: u32,
    discover_id: u32,
    data_id: u32,
    native: Option<Arc<Mutex<NativeXdp>>>,
}

impl PersistentAttachment {
    pub fn create(ifindex: u32, programs: &Programs, pin_root: &Path) -> io::Result<Self> {
        validate_ifindex(ifindex)?;
        if programs.native_dispatch.is_some() {
            require_empty_tcx(&query_tcx(ifindex, BPF_TCX_INGRESS)?)?;
            require_empty_tcx(&query_tcx(ifindex, BPF_TCX_EGRESS)?)?;
        }
        let root = private_bpffs(pin_root)?;
        pin_program(root.as_fd(), c"guard", programs.discover.as_fd())?;
        // A partial pair is retained as explicit startup-failure custody.
        pin_program(root.as_fd(), c"data", programs.data.as_fd())?;
        if !xdp_absent(ifindex)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "foreign or stale XDP attachment",
            ));
        }
        let attachment = Self {
            ifindex,
            discover_id: programs.discover_id,
            data_id: programs.data_id,
            native: if programs.native_dispatch.is_some() {
                Some(Arc::new(Mutex::new(NativeXdp {
                    root,
                    guard: programs.discover.try_clone()?,
                    data: programs.data.try_clone()?,
                    guard_id: programs.discover_id,
                    data_id: programs.data_id,
                    active: false,
                    retired: None,
                    pending: None,
                    pin_ready: false,
                    gate: None,
                    updates: None,
                })))
            } else {
                None
            },
        };
        set_xdp(ifindex, programs.discover.as_raw_fd(), None)?;
        require_native(xdp_state(ifindex)?, programs.discover_id)?;
        if let Some(dispatch) = &programs.native_dispatch {
            *dispatch
                .attachment
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))? =
                Some(attachment.clone());
        }
        Ok(attachment)
    }

    pub fn replace(&self, programs: &Programs) -> io::Result<XdpState> {
        self.check_programs(programs)?;
        if let Some(native) = &self.native {
            return native
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))?
                .activate(self.ifindex);
        }
        require_native(xdp_state(self.ifindex)?, self.discover_id)?;
        set_xdp(
            self.ifindex,
            programs.data.as_raw_fd(),
            Some(programs.discover.as_raw_fd()),
        )?;
        require_native(xdp_state(self.ifindex)?, self.data_id)
    }

    /// Reinstall the selected-traffic DROP guard before withdrawing any XSK.
    pub fn guard(&self, programs: &Programs) -> io::Result<()> {
        self.check_programs(programs)?;
        if let Some(native) = &self.native {
            return native
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))?
                .guard(self.ifindex);
        }
        let state = xdp_state(self.ifindex)?;
        if state.prog_id == self.discover_id {
            require_native(state, self.discover_id)?;
            return Ok(());
        }
        require_native(state, self.data_id)?;
        set_xdp(
            self.ifindex,
            programs.discover.as_raw_fd(),
            Some(programs.data.as_raw_fd()),
        )?;
        require_native(xdp_state(self.ifindex)?, self.discover_id)?;
        Ok(())
    }

    fn check_programs(&self, programs: &Programs) -> io::Result<()> {
        if programs.discover_id != self.discover_id || programs.data_id != self.data_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "foreign XDP programs",
            ));
        }
        Ok(())
    }

    fn current_data_id(&self) -> io::Result<u32> {
        self.native.as_ref().map_or(Ok(self.data_id), |native| {
            Ok(native
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))?
                .data_id)
        })
    }

    fn publish_native(&self, program: BorrowedFd<'_>, id: u32) -> io::Result<()> {
        self.native
            .as_ref()
            .ok_or_else(|| invalid_data("Native XDP attachment missing"))?
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?
            .publish(self.ifindex, program, id)
    }

    fn finish_native_publication(&self) -> io::Result<()> {
        self.native
            .as_ref()
            .ok_or_else(|| invalid_data("Native XDP attachment missing"))?
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?
            .finish_publication()
    }
}

struct NativeXdp {
    root: OwnedFd,
    guard: OwnedFd,
    data: OwnedFd,
    guard_id: u32,
    data_id: u32,
    active: bool,
    retired: Option<OwnedFd>,
    pending: Option<OwnedFd>,
    pin_ready: bool,
    gate: Option<Arc<NativeTcxAttachment>>,
    updates: Option<NativeXdpUpdates>,
}

fn pinned_program_id(
    root: BorrowedFd<'_>,
    name: &std::ffi::CStr,
    expected_type: u32,
) -> io::Result<u32> {
    #[repr(C)]
    struct Get {
        pathname: u64,
        fd: u32,
        flags: u32,
        path_fd: i32,
        pad: u32,
    }
    let fd = bpf_fd(
        7,
        &mut Get {
            pathname: name.as_ptr() as u64,
            fd: 0,
            flags: BPF_F_PATH_FD,
            path_fd: root.as_raw_fd(),
            pad: 0,
        },
    )?;
    let mut info = ProgInfo::default();
    object_info(fd.as_fd(), &mut info)?;
    validate_pinned_program(&info, expected_type)?;
    Ok(info.id)
}

fn validate_pinned_program(info: &ProgInfo, expected_type: u32) -> io::Result<()> {
    if info.kind != expected_type || info.id == 0 {
        return Err(invalid_data(
            "Native program pin has the wrong type or zero ID",
        ));
    }
    Ok(())
}

fn unlink_program(root: BorrowedFd<'_>, name: &std::ffi::CStr, expected: u32) -> io::Result<()> {
    if pinned_program_id(root, name, BPF_PROG_TYPE_XDP)? != expected {
        return Err(invalid_data("Native program pin replaced"));
    }
    // SAFETY: the private directory and static NUL-terminated name remain live.
    if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl NativeXdp {
    fn register_gate(&mut self, owner: Arc<NativeTcxAttachment>) -> io::Result<()> {
        self.require_resolved()?;
        if self.gate.is_some() || self.active || self.retired.is_some() {
            return Err(invalid_data(
                "Native gate owner cannot be registered twice or while active",
            ));
        }
        self.gate = Some(owner);
        Ok(())
    }

    fn require_gate_with(
        &self,
        check: impl FnOnce(&NativeTcxAttachment) -> io::Result<()>,
    ) -> io::Result<()> {
        let gate = self
            .gate
            .as_ref()
            .ok_or_else(|| invalid_data("Native ingress gate owner is not registered"))?;
        check(gate)
    }

    fn publish_with<T>(
        &mut self,
        check: impl FnOnce(&NativeTcxAttachment) -> io::Result<()>,
        update: impl FnOnce(&mut Self) -> io::Result<T>,
    ) -> io::Result<T> {
        self.require_resolved()?;
        self.require_gate_with(check)?;
        update(self)
    }

    fn selected_id(&self) -> u32 {
        if self.active {
            self.data_id
        } else {
            self.guard_id
        }
    }

    fn guard_with(
        &mut self,
        update: impl FnOnce(RawFd, RawFd) -> io::Result<()>,
        readback: impl FnOnce(u32) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.active {
            update(self.guard.as_raw_fd(), self.data.as_raw_fd())?;
            self.active = false;
        }
        readback(self.guard_id)
    }

    fn guard(&mut self, ifindex: u32) -> io::Result<()> {
        self.require_resolved()?;
        let updates = self.updates.clone();
        let mut watch = updates.as_ref().map(NativeXdpUpdates::lock);
        let state = xdp_state(ifindex)?;
        if state.prog_id == self.guard_id {
            require_native(state, self.guard_id)?;
            self.active = false;
            return watch.as_mut().map_or(Ok(()), |watch| watch.check());
        }
        require_native(state, self.selected_id())?;
        let (guard_id, data_id) = (self.guard_id, self.data_id);
        let mut observation = Ok(());
        let mut acknowledged = false;
        let result = self.guard_with(
            |new, old| {
                // SAFETY: NativeXdp retains both program FDs throughout this operation.
                let outcome = watch.as_mut().map_or_else(
                    || NativeUpdateOutcome {
                        transport: set_xdp(ifindex, new, Some(old)),
                        observation: Ok(()),
                    },
                    |watch| {
                        watch.update(
                            ifindex,
                            unsafe { BorrowedFd::borrow_raw(new) },
                            guard_id,
                            unsafe { BorrowedFd::borrow_raw(old) },
                            data_id,
                            true,
                        )
                    },
                );
                acknowledged = outcome.transport.is_ok();
                observation = outcome.observation;
                outcome.transport.map_err(io::Error::from)
            },
            |id| require_native(xdp_state(ifindex)?, id).map(|_| ()),
        );
        if acknowledged
            && result.is_err()
            && let Some(watch) = &mut watch
        {
            watch.invalidate();
        }
        combine_observation(result, observation)
    }

    fn activate(&mut self, ifindex: u32) -> io::Result<XdpState> {
        self.require_resolved()?;
        let updates = self.updates.clone();
        let mut watch = updates.as_ref().map(NativeXdpUpdates::lock);
        if let Some(watch) = &mut watch {
            watch.check()?;
        }
        require_native(xdp_state(ifindex)?, self.selected_id())?;
        let (data_id, guard_id) = (self.data_id, self.guard_id);
        let mut observation = Ok(());
        let mut acknowledged = false;
        let result = self.activate_with(
            NativeTcxAttachment::check,
            |new, old| {
                // SAFETY: NativeXdp retains both program FDs throughout this operation.
                let outcome = watch.as_mut().map_or_else(
                    || NativeUpdateOutcome {
                        transport: set_xdp(ifindex, new, Some(old)),
                        observation: Ok(()),
                    },
                    |watch| {
                        watch.update(
                            ifindex,
                            unsafe { BorrowedFd::borrow_raw(new) },
                            data_id,
                            unsafe { BorrowedFd::borrow_raw(old) },
                            guard_id,
                            false,
                        )
                    },
                );
                acknowledged = outcome.transport.is_ok();
                observation = outcome.observation;
                outcome.transport.map_err(io::Error::from)
            },
            |id| require_native(xdp_state(ifindex)?, id),
        );
        if acknowledged
            && result.is_err()
            && let Some(watch) = &mut watch
        {
            watch.invalidate();
        }
        combine_observation(result, observation)
    }

    fn activate_with(
        &mut self,
        check: impl FnOnce(&NativeTcxAttachment) -> io::Result<()>,
        update: impl FnOnce(RawFd, RawFd) -> io::Result<()>,
        readback: impl FnOnce(u32) -> io::Result<XdpState>,
    ) -> io::Result<XdpState> {
        self.require_resolved()?;
        self.require_gate_with(check)?;
        if !self.active {
            update(self.data.as_raw_fd(), self.guard.as_raw_fd())?;
            self.active = true;
        }
        readback(self.data_id)
    }

    fn require_resolved(&self) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(invalid_data(
                "Native XDP selection outcome unresolved; candidate retained",
            ));
        }
        Ok(())
    }

    fn publication_selection(
        &mut self,
        next: OwnedFd,
        result: Result<(), XdpUpdateError>,
        discard_rejected: impl FnOnce(&Self) -> io::Result<()>,
    ) -> io::Result<OwnedFd> {
        match result {
            Ok(()) => Ok(next),
            Err(error) => {
                if matches!(
                    &error,
                    XdpUpdateError::NotAttempted(_) | XdpUpdateError::Rejected(_)
                ) {
                    match discard_rejected(self) {
                        Ok(()) => return Err(error.into()),
                        Err(discard_error) => {
                            self.pending = Some(next);
                            self.pin_ready = false;
                            return Err(discard_error);
                        }
                    }
                }
                // An unacknowledged request can still select the pinned candidate.
                self.pending = Some(next);
                self.pin_ready = false;
                Err(error.into())
            }
        }
    }

    fn publish(&mut self, ifindex: u32, program: BorrowedFd<'_>, id: u32) -> io::Result<()> {
        self.publish_with(NativeTcxAttachment::check, |state| {
            state.publish_checked(ifindex, program, id)
        })
    }

    fn publish_checked(
        &mut self,
        ifindex: u32,
        program: BorrowedFd<'_>,
        id: u32,
    ) -> io::Result<()> {
        if self.retired.is_some() {
            return Err(invalid_data("prior Native data publication is not retired"));
        }
        let updates = self.updates.clone();
        let mut watch = updates.as_ref().map(NativeXdpUpdates::lock);
        if let Some(watch) = &mut watch {
            watch.check()?;
        }
        let mut info = ProgInfo::default();
        object_info(program, &mut info)?;
        validate_pinned_program(&info, BPF_PROG_TYPE_XDP)?;
        if info.id != id {
            return Err(invalid_data("Native candidate FD/ID mismatch"));
        }
        require_native(xdp_state(ifindex)?, self.selected_id())?;
        if pinned_program_id(self.root.as_fd(), c"data", BPF_PROG_TYPE_XDP)? != self.data_id {
            return Err(invalid_data("Native data pin identity changed"));
        }
        let next = program.try_clone_to_owned()?;
        pin_program(self.root.as_fd(), c"data-next", program)?;
        self.pin_ready = false;
        let outcome = if self.active {
            watch.as_mut().map_or_else(
                || NativeUpdateOutcome {
                    transport: set_xdp(ifindex, program.as_raw_fd(), Some(self.data.as_raw_fd())),
                    observation: Ok(()),
                },
                |watch| watch.update(ifindex, program, id, self.data.as_fd(), self.data_id, false),
            )
        } else {
            NativeUpdateOutcome {
                transport: Ok(()),
                observation: Ok(()),
            }
        };
        let prior = self.selected_id();
        let selection = self.publication_selection(next, outcome.transport, |state| {
            require_native(xdp_state(ifindex)?, prior)?;
            unlink_program(state.root.as_fd(), c"data-next", id)
        });
        let next = match selection {
            Ok(next) => next,
            Err(error) => return combine_observation(Err(error), outcome.observation),
        };
        self.retired = Some(std::mem::replace(&mut self.data, next));
        self.data_id = id;
        let bookkeeping = (|| {
            require_native(xdp_state(ifindex)?, self.selected_id())?;
            // Grace retains the old FD after atomically promoting its successor's pin.
            let result = unsafe {
                libc::renameat(
                    self.root.as_raw_fd(),
                    c"data-next".as_ptr(),
                    self.root.as_raw_fd(),
                    c"data".as_ptr(),
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            if pinned_program_id(self.root.as_fd(), c"data", BPF_PROG_TYPE_XDP)? != id {
                return Err(invalid_data("Native promoted data pin identity changed"));
            }
            require_native(xdp_state(ifindex)?, self.selected_id())?;
            self.pin_ready = true;
            Ok(())
        })();
        if bookkeeping.is_err()
            && let Some(watch) = &mut watch
        {
            watch.invalidate();
        }
        combine_observation(bookkeeping, outcome.observation)
    }

    fn finish_publication(&mut self) -> io::Result<()> {
        self.require_resolved()?;
        if self.retired.is_some() {
            if !self.pin_ready {
                return Err(invalid_data("Native data pin replacement did not complete"));
            }
            self.pin_ready = false;
            self.retired.take();
        }
        Ok(())
    }
}

fn combine_observation<T>(operation: io::Result<T>, observation: io::Result<()>) -> io::Result<T> {
    match (operation, observation) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(observation)) => Err(io::Error::new(
            operation.kind(),
            format!("{operation}; topology observation also failed: {observation}"),
        )),
    }
}

fn withdraw_recording_hooks_with(
    guard: impl FnOnce() -> io::Result<()>,
    withdraw: impl FnOnce() -> io::Result<()>,
    clear: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let guarded = guard();
    let withdrawn = withdraw();
    let cleared = clear();
    combine_observation(combine_observation(guarded, withdrawn), cleared)
}

fn private_bpffs(path: &Path) -> io::Result<OwnedFd> {
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // SAFETY: the statfs output structure accepts an all-zero initialization.
    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: statfs is writable and the descriptor denotes the opened directory.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut statfs) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if statfs.f_type as u32 != 0xcafe4a11 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XDP pin root must be bpffs",
        ));
    }
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no pointer arguments or failure case.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "XDP pin root must be private and owned by the effective user",
        ));
    }
    Ok(directory.into())
}

fn pin_program(
    root: BorrowedFd<'_>,
    name: &std::ffi::CStr,
    program: BorrowedFd<'_>,
) -> io::Result<()> {
    #[repr(C)]
    struct PinAttr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
        path_fd: i32,
        padding: u32,
    }
    bpf(
        BPF_OBJ_PIN,
        &mut PinAttr {
            pathname: name.as_ptr() as u64,
            bpf_fd: program.as_raw_fd() as u32,
            file_flags: BPF_F_PATH_FD,
            path_fd: root.as_raw_fd(),
            padding: 0,
        },
    )?;
    Ok(())
}

pub struct Attachment {
    fd: OwnedFd,
    ifindex: u32,
    id: u32,
    discover_id: u32,
    data_id: u32,
}

impl Attachment {
    pub fn create(ifindex: u32, programs: &Programs) -> io::Result<Self> {
        validate_ifindex(ifindex)?;
        let fd = bpf_fd(
            BPF_LINK_CREATE,
            &mut LinkCreateAttr {
                prog_fd: programs.discover.as_raw_fd() as u32,
                target_ifindex: ifindex,
                attach_type: BPF_XDP,
                flags: XDP_FLAGS_DRV_MODE,
            },
        )?;
        let identity = (|| {
            let mut info = LinkInfo::default();
            object_info(fd.as_fd(), &mut info)?;
            if info.kind != BPF_LINK_TYPE_XDP
                || info.id == 0
                || info.prog_id != programs.discover_id
                || info.ifindex != ifindex
            {
                return Err(invalid_data("native XDP link identity readback mismatch"));
            }
            require_native(xdp_state(ifindex)?, programs.discover_id)?;
            Ok(info.id)
        })();
        let id = match identity {
            Ok(id) => id,
            Err(error) => {
                // Detaching on a readback error could expose the still-live local upstream.
                std::mem::forget(fd);
                return Err(error);
            }
        };
        Ok(Self {
            fd,
            ifindex,
            id,
            discover_id: programs.discover_id,
            data_id: programs.data_id,
        })
    }

    pub fn replace(&self, programs: &Programs) -> io::Result<XdpState> {
        if programs.discover_id != self.discover_id || programs.data_id != self.data_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "programs do not belong to this attachment",
            ));
        }
        bpf(
            BPF_LINK_UPDATE,
            &mut LinkUpdateAttr {
                link_fd: self.fd.as_raw_fd() as u32,
                new_prog_fd: programs.data.as_raw_fd() as u32,
                flags: BPF_F_REPLACE,
                old_prog_fd: programs.discover.as_raw_fd() as u32,
            },
        )?;
        let mut info = LinkInfo::default();
        object_info(self.fd.as_fd(), &mut info)?;
        if info.kind != BPF_LINK_TYPE_XDP
            || info.id != self.id
            || info.prog_id != self.data_id
            || info.ifindex != self.ifindex
        {
            return Err(invalid_data("updated XDP link identity readback mismatch"));
        }
        require_native(xdp_state(self.ifindex)?, self.data_id)
    }

    /// Reinstall the selected-traffic DROP guard before withdrawing any XSK.
    pub fn guard(&self, programs: &Programs) -> io::Result<()> {
        if programs.discover_id != self.discover_id || programs.data_id != self.data_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "foreign XDP programs",
            ));
        }
        bpf(
            BPF_LINK_UPDATE,
            &mut LinkUpdateAttr {
                link_fd: self.fd.as_raw_fd() as u32,
                new_prog_fd: programs.discover.as_raw_fd() as u32,
                flags: BPF_F_REPLACE,
                old_prog_fd: programs.data.as_raw_fd() as u32,
            },
        )?;
        require_native(xdp_state(self.ifindex)?, self.discover_id)?;
        Ok(())
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

impl AsFd for Attachment {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Attachment {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpState {
    pub attached: u8,
    pub prog_id: u32,
    pub drv_prog_id: u32,
    pub skb_prog_id: u32,
    pub hw_prog_id: u32,
    pub flags: u32,
}

pub(crate) fn require_native(state: XdpState, program: u32) -> io::Result<XdpState> {
    if state.attached != 1
        || state.prog_id != program
        || state.drv_prog_id != program
        || state.skb_prog_id != 0
        || state.hw_prog_id != 0
    {
        return Err(invalid_data("native DRV XDP attachment readback mismatch"));
    }
    Ok(state)
}

pub fn xdp_absent(ifindex: u32) -> io::Result<bool> {
    let state = xdp_state(ifindex)?;
    Ok(state.attached == 0
        && state.prog_id == 0
        && state.drv_prog_id == 0
        && state.skb_prog_id == 0
        && state.hw_prog_id == 0)
}

fn validate_ifindex(ifindex: u32) -> io::Result<()> {
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid XDP interface index",
        ));
    }
    Ok(())
}

pub fn xdp_state(ifindex: u32) -> io::Result<XdpState> {
    validate_ifindex(ifindex)?;
    let mut request = [0u8; 32];
    request[..4].copy_from_slice(&32u32.to_ne_bytes());
    request[4..6].copy_from_slice(&18u16.to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    exchange_netlink(&request, |bytes| parse_link_messages(bytes, 1, ifindex))
}

fn xdp_update_request(ifindex: u32, program: RawFd, expected: Option<RawFd>) -> ([u8; 60], usize) {
    let mut request = [0u8; 60];
    let length = if expected.is_some() { 60 } else { 52 };
    request[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&19u16.to_ne_bytes()); // RTM_SETLINK
    request[6..8].copy_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    request[32..34].copy_from_slice(&((length - 32) as u16).to_ne_bytes());
    request[34..36].copy_from_slice(&(43u16 | 0x8000).to_ne_bytes()); // IFLA_XDP
    let flags = XDP_FLAGS_DRV_MODE
        | if expected.is_some() {
            XDP_FLAGS_REPLACE
        } else {
            XDP_FLAGS_UPDATE_IF_NOEXIST
        };
    for (offset, kind, value) in [(36, 1u16, program as u32), (44, 3, flags)] {
        request[offset..offset + 2].copy_from_slice(&8u16.to_ne_bytes());
        request[offset + 2..offset + 4].copy_from_slice(&kind.to_ne_bytes());
        request[offset + 4..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    if let Some(expected) = expected {
        request[52..54].copy_from_slice(&8u16.to_ne_bytes());
        request[54..56].copy_from_slice(&8u16.to_ne_bytes()); // IFLA_XDP_EXPECTED_FD
        request[56..60].copy_from_slice(&expected.to_ne_bytes());
    }
    (request, length)
}

pub(crate) enum XdpUpdateError {
    NotAttempted(io::Error),
    Rejected(io::Error),
    Uncertain(io::Error),
}

impl From<XdpUpdateError> for io::Error {
    fn from(error: XdpUpdateError) -> Self {
        match error {
            XdpUpdateError::NotAttempted(error) | XdpUpdateError::Rejected(error) => error,
            XdpUpdateError::Uncertain(error) => io::Error::new(
                error.kind(),
                format!("XDP update outcome unknown; retain pins and owners: {error}"),
            ),
        }
    }
}

pub(crate) fn set_xdp(
    ifindex: u32,
    program: RawFd,
    expected: Option<RawFd>,
) -> Result<(), XdpUpdateError> {
    let (request, length) = xdp_update_request(ifindex, program, expected);
    let mut rejected = false;
    exchange_netlink(&request[..length], |bytes| {
        let result = parse_setlink_ack(bytes, 1);
        rejected = result
            .as_ref()
            .is_err_and(|error| error.raw_os_error().is_some());
        result
    })
    .map_err(|error| {
        if rejected {
            XdpUpdateError::Rejected(error)
        } else {
            XdpUpdateError::Uncertain(error)
        }
    })
}

fn parse_setlink_ack(mut bytes: &[u8], sequence: u32) -> io::Result<Option<()>> {
    let mut outcome = None;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(invalid_data("truncated netlink ACK header"));
        }
        let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        if length < 16 || length > bytes.len() {
            return Err(invalid_data("invalid netlink ACK extent"));
        }
        let advance = aligned_extent(length, bytes.len())?;
        if u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) == sequence {
            if u16::from_ne_bytes(bytes[6..8].try_into().unwrap()) & 0x10 != 0 {
                return Err(invalid_data("interrupted netlink ACK"));
            }
            if u16::from_ne_bytes(bytes[4..6].try_into().unwrap()) == 2 {
                if length < 36 {
                    return Err(invalid_data("truncated netlink ACK request"));
                }
                let request = &bytes[20..36];
                if u32::from_ne_bytes(request[..4].try_into().unwrap()) < 32
                    || u16::from_ne_bytes(request[4..6].try_into().unwrap()) != 19
                    || u16::from_ne_bytes(request[6..8].try_into().unwrap()) & 5 != 5
                    || u32::from_ne_bytes(request[8..12].try_into().unwrap()) != sequence
                {
                    return Err(invalid_data("netlink ACK request identity mismatch"));
                }
                let error = i32::from_ne_bytes(bytes[16..20].try_into().unwrap());
                if error > 0 || error == i32::MIN || outcome.replace(error).is_some() {
                    return Err(invalid_data("invalid or duplicate netlink ACK outcome"));
                }
            }
        }
        bytes = &bytes[advance..];
    }
    match outcome {
        Some(0) => Ok(Some(())),
        Some(error) => Err(io::Error::from_raw_os_error(-error)),
        None => Ok(None),
    }
}

fn exchange_netlink<T>(
    request: &[u8],
    parse: impl FnMut(&[u8]) -> io::Result<Option<T>>,
) -> io::Result<T> {
    let mut buffer = [0u8; 16_384];
    exchange_netlink_buffer(request, &mut buffer, parse)
}

pub(crate) fn exchange_netlink_buffer<T>(
    request: &[u8],
    buffer: &mut [u8],
    mut parse: impl FnMut(&[u8]) -> io::Result<Option<T>>,
) -> io::Result<T> {
    // SAFETY: socket has no pointer arguments and returns a newly owned descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is the newly created descriptor, transferred exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: an all-zero sockaddr_nl is valid before setting its family.
    let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: local points to a complete sockaddr_nl for the supplied length.
    if unsafe {
        libc::bind(
            raw,
            (&local as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let kernel = local;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: request and kernel are live buffers matching their supplied lengths.
        let sent = unsafe {
            libc::sendto(
                raw,
                request.as_ptr().cast(),
                request.len(),
                libc::MSG_DONTWAIT,
                (&kernel as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent >= 0 {
            if sent as usize != request.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short route netlink send",
                ));
            }
            break;
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(error);
        }
        wait_netlink(fd.as_fd(), libc::POLLOUT, deadline)?;
    }
    loop {
        wait_netlink(fd.as_fd(), libc::POLLIN, deadline)?;
        let mut source = local;
        let mut source_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: buffer/source are writable for the lengths supplied to recvfrom.
        let received = unsafe {
            libc::recvfrom(
                raw,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                (&mut source as *mut libc::sockaddr_nl).cast(),
                &mut source_len,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        let received = received as usize;
        if received == 0 || received > buffer.len() {
            return Err(invalid_data("empty or truncated route netlink datagram"));
        }
        if source_len as usize != size_of::<libc::sockaddr_nl>()
            || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || source.nl_pid != 0
        {
            return Err(invalid_data("route netlink reply is not from the kernel"));
        }
        if let Some(reply) = parse(&buffer[..received])? {
            return Ok(reply);
        }
    }
}

pub(crate) fn wait_netlink(
    fd: BorrowedFd<'_>,
    events: libc::c_short,
    deadline: Instant,
) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() && events & libc::POLLIN == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "route netlink deadline expired",
            ));
        }
        // RTM_SETLINK may execute synchronously inside sendto beyond the deadline.
        // Its queued ACK still owns the outcome; poll it once without extending the wait.
        let milliseconds = if remaining.is_zero() {
            0
        } else {
            remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32
        };
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: pollfd is a live single-element array for the duration of poll.
        let result = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("RTM_GETLINK socket poll error"));
        }
        if result > 0 && pollfd.revents & events != 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "route netlink deadline expired",
            ));
        }
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn aligned_extent(length: usize, remaining: usize) -> io::Result<usize> {
    let aligned = length
        .checked_add(3)
        .ok_or_else(|| invalid_data("netlink length overflow"))?
        & !3;
    if aligned > remaining && length != remaining {
        return Err(invalid_data("truncated netlink alignment padding"));
    }
    Ok(aligned.min(remaining))
}

pub(crate) fn attributes<'a>(
    bytes: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    raw_attributes(bytes, |kind, value| visit(kind & 0x3fff, value))
}

pub(crate) fn raw_attributes<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid_data("truncated netlink attribute header"));
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if length < 4 || length > bytes.len() {
            return Err(invalid_data("invalid netlink attribute extent"));
        }
        let advance = aligned_extent(length, bytes.len())?;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        visit(kind, &bytes[4..length])?;
        bytes = &bytes[advance..];
    }
    Ok(())
}

fn parse_xdp_attributes(bytes: &[u8]) -> io::Result<XdpState> {
    let mut state = XdpState::default();
    attributes(bytes, |kind, value| {
        if kind == 2 {
            if value.len() != 1 {
                return Err(invalid_data("invalid IFLA_XDP_ATTACHED extent"));
            }
            state.attached = value[0];
        } else if (3..=7).contains(&kind) {
            let value = u32::from_ne_bytes(
                value
                    .try_into()
                    .map_err(|_| invalid_data("invalid IFLA_XDP integer extent"))?,
            );
            match kind {
                3 => state.flags = value,
                4 => state.prog_id = value,
                5 => state.drv_prog_id = value,
                6 => state.skb_prog_id = value,
                7 => state.hw_prog_id = value,
                _ => unreachable!(),
            }
        }
        Ok(())
    })?;
    Ok(state)
}

pub(crate) fn strict_native_xdp(bytes: &[u8], program: u32) -> io::Result<XdpState> {
    let mut seen = 0u16;
    raw_attributes(bytes, |kind, value| {
        if !(2..=7).contains(&kind) || kind == 3 || seen & (1 << kind) != 0 {
            return Err(invalid_data(
                "unknown, request-only or duplicate Native XDP field",
            ));
        }
        seen |= 1 << kind;
        if value.len() != if kind == 2 { 1 } else { 4 } {
            return Err(invalid_data("invalid Native XDP field extent"));
        }
        Ok(())
    })?;
    if seen & ((1 << 2) | (1 << 4) | (1 << 5)) != (1 << 2) | (1 << 4) | (1 << 5) {
        return Err(invalid_data("missing mandatory Native XDP field"));
    }
    require_native(parse_xdp_attributes(bytes)?, program)
}

fn parse_link_messages(
    mut bytes: &[u8],
    sequence: u32,
    ifindex: u32,
) -> io::Result<Option<XdpState>> {
    let mut found = None;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(invalid_data("truncated netlink message header"));
        }
        let length = usize::try_from(u32::from_ne_bytes(bytes[..4].try_into().unwrap()))
            .map_err(|_| invalid_data("netlink message length exceeds usize"))?;
        if length < 16 || length > bytes.len() {
            return Err(invalid_data("invalid netlink message extent"));
        }
        let advance = aligned_extent(length, bytes.len())?;
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        let actual_sequence = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        if actual_sequence == sequence {
            if flags & 0x10 != 0 {
                return Err(invalid_data("interrupted RTM_GETLINK reply"));
            }
            let body = &bytes[16..length];
            match kind {
                2 => {
                    let error = i32::from_ne_bytes(
                        body.get(..4)
                            .ok_or_else(|| invalid_data("truncated netlink error"))?
                            .try_into()
                            .unwrap(),
                    );
                    if error < 0 {
                        return Err(io::Error::from_raw_os_error(
                            error
                                .checked_neg()
                                .ok_or_else(|| invalid_data("invalid netlink errno"))?,
                        ));
                    }
                    if error != 0 {
                        return Err(invalid_data("invalid positive netlink errno"));
                    }
                }
                3 if found.is_none() => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "RTM_GETLINK did not return the interface",
                    ));
                }
                4 => return Err(invalid_data("RTM_GETLINK overrun")),
                16 => {
                    if body.len() < 16 {
                        return Err(invalid_data("truncated ifinfomsg"));
                    }
                    let actual_index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
                    if actual_index == ifindex as i32 {
                        let mut state = XdpState::default();
                        attributes(&body[16..], |kind, value| {
                            if kind == 43 {
                                state = parse_xdp_attributes(value)?;
                            }
                            Ok(())
                        })?;
                        if found.replace(state).is_some() {
                            return Err(invalid_data("duplicate RTM_GETLINK interface reply"));
                        }
                    }
                }
                _ => {}
            }
        }
        bytes = &bytes[advance..];
    }
    Ok(found)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl Insn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        let regs = if cfg!(target_endian = "little") {
            dst | src << 4
        } else {
            dst << 4 | src
        };
        Self {
            code,
            regs,
            off,
            imm,
        }
    }
}

const LD_MAP: u8 = 0x18;
const LDX_W: u8 = 0x61;
const LDX_H: u8 = 0x69;
const LDX_B: u8 = 0x71;
const ST_W: u8 = 0x62;
const STX_W: u8 = 0x63;
const ATOMIC_ADD_DW: u8 = 0xdb;
const MOV_K: u8 = 0xb7;
const MOV_X: u8 = 0xbf;
const ADD_K: u8 = 0x07;
const ADD_X: u8 = 0x0f;
const AND_K: u8 = 0x57;
const LSH_K: u8 = 0x67;
const RSH_K: u8 = 0x77;
const BE16: u8 = 0xdc;
const JA: u8 = 0x05;
const JEQ_K: u8 = 0x15;
const JGT_K: u8 = 0x25;
const JGT_X: u8 = 0x2d;
const JGE_K: u8 = 0x35;
const JSET_K: u8 = 0x45;
const JNE_K: u8 = 0x55;
const JNE_X: u8 = 0x5d;
const JNE32_K: u8 = 0x56;
const JLT_K: u8 = 0xa5;
const CALL: u8 = 0x85;
const EXIT: u8 = 0x95;

#[derive(Clone, Copy)]
#[repr(usize)]
enum Label {
    Pass,
    Drop,
    Fragments,
    Options,
    Malformed,
    CountDrop,
    Ipv4,
    Ipv6,
    Selected,
}

struct Program {
    insns: Vec<Insn>,
    len: usize,
    flags: u32,
    ifindex: u32,
    pub(super) kfunc_btf: Option<OwnedFd>,
}

struct Builder {
    program: Program,
    labels: [usize; 9],
    jumps: [(usize, Label); 512],
    jump_count: usize,
}

impl Builder {
    fn new() -> Self {
        Self {
            program: Program {
                insns: Vec::with_capacity(4096),
                len: 0,
                flags: 0,
                ifindex: 0,
                kfunc_btf: None,
            },
            labels: [usize::MAX; 9],
            jumps: [(0, Label::Pass); 512],
            jump_count: 0,
        }
    }

    fn reserve(&mut self, additional: usize) -> io::Result<()> {
        if self
            .program
            .len
            .checked_add(additional)
            .is_none_or(|length| length > MAX_PROGRAM_INSNS)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BPF instruction limit exceeded",
            ));
        }
        self.program
            .insns
            .try_reserve_exact(additional)
            .map_err(|error| io::Error::other(format!("BPF instruction reservation: {error}")))
    }

    fn emit(&mut self, instruction: Insn) -> usize {
        let at = self.program.len;
        self.program.insns.push(instruction);
        self.program.len += 1;
        at
    }

    fn jump(&mut self, instruction: Insn, target: Label) {
        let at = self.emit(instruction);
        self.jumps[self.jump_count] = (at, target);
        self.jump_count += 1;
    }

    fn label(&mut self, label: Label) {
        assert_eq!(self.labels[label as usize], usize::MAX);
        self.labels[label as usize] = self.program.len;
    }

    fn map_fd(&mut self, fd: RawFd) {
        self.emit(Insn::new(LD_MAP, 1, 1, 0, fd));
        self.emit(Insn::default());
    }

    fn bound(&mut self, length: i32, target: Label) {
        self.emit(Insn::new(MOV_X, 0, 6, 0, 0));
        self.emit(Insn::new(ADD_K, 0, 0, 0, length));
        self.jump(Insn::new(JGT_X, 0, 7, 0, 0), target);
    }

    fn count(&mut self, counters_fd: RawFd) {
        self.map_fd(counters_fd);
        self.emit(Insn::new(MOV_X, 2, 10, 0, 0));
        self.emit(Insn::new(ADD_K, 2, 0, 0, -4));
        self.emit(Insn::new(CALL, 0, 0, 0, 1));
        self.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        self.emit(Insn::new(MOV_K, 1, 0, 0, 1));
        self.emit(Insn::new(ATOMIC_ADD_DW, 0, 1, 0, 0));
    }

    fn finish(mut self) -> io::Result<Program> {
        for &(at, label) in &self.jumps[..self.jump_count] {
            let target = self.labels[label as usize];
            if target >= self.program.len {
                return Err(io::Error::other("unresolved XDP program label"));
            }
            let offset = isize::try_from(target).unwrap() - isize::try_from(at).unwrap() - 1;
            self.program.insns[at].off = i16::try_from(offset)
                .map_err(|_| io::Error::other("XDP jump offset exceeds i16"))?;
        }
        Ok(self.program)
    }
}

fn build_program(
    capture: &Capture,
    queues: u32,
    counters_fd: RawFd,
    xsks_fd: RawFd,
    data: bool,
) -> io::Result<Program> {
    validate_queues(queues)?;
    let mut b = Builder::new();
    b.emit(Insn::new(LDX_W, 6, 1, 0, 0));
    b.emit(Insn::new(LDX_W, 7, 1, 4, 0));
    b.emit(Insn::new(LDX_W, 8, 1, 16, 0));
    b.bound(14, Label::Pass);
    b.emit(Insn::new(LDX_H, 0, 6, 12, 0));
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, u16::from_ne_bytes([8, 0]) as i32),
        Label::Pass,
    );
    b.bound(34, Label::Pass);
    b.emit(Insn::new(LDX_B, 0, 6, 23, 0));
    b.jump(
        Insn::new(JNE_K, 0, 0, 0, i32::from(capture.protocol.number())),
        Label::Pass,
    );
    b.emit(Insn::new(LDX_W, 0, 6, 26, 0));
    b.jump(
        Insn::new(
            JNE32_K,
            0,
            0,
            0,
            u32::from_ne_bytes(capture.client.ip().octets()) as i32,
        ),
        Label::Pass,
    );
    b.emit(Insn::new(LDX_W, 0, 6, 30, 0));
    b.jump(
        Insn::new(
            JNE32_K,
            0,
            0,
            0,
            u32::from_ne_bytes(capture.service.ip().octets()) as i32,
        ),
        Label::Pass,
    );
    // The exclusive IP/protocol fence must precede ports and MAC guards: later
    // fragments have no ports and must never reach the colocated kernel service.
    b.emit(Insn::new(LDX_H, 0, 6, 20, 0));
    b.jump(
        Insn::new(JSET_K, 0, 0, 0, u16::from_be(0x3fff) as i32),
        Label::Fragments,
    );
    b.emit(Insn::new(LDX_B, 0, 6, 14, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 0x40), Label::Malformed);
    b.emit(Insn::new(LDX_B, 0, 6, 14, 0));
    b.emit(Insn::new(AND_K, 0, 0, 0, 0x0f));
    b.jump(Insn::new(JNE_K, 0, 0, 0, 5), Label::Options);
    let l4_min = match capture.protocol {
        Protocol::Tcp => 20,
        Protocol::Udp => 8,
    };
    b.emit(Insn::new(LDX_H, 9, 6, 16, 0));
    b.emit(Insn::new(BE16, 9, 0, 0, 16));
    b.jump(Insn::new(JLT_K, 9, 0, 0, 20 + l4_min), Label::Malformed);
    b.jump(Insn::new(JGT_K, 9, 0, 0, 1500), Label::Malformed);
    b.emit(Insn::new(MOV_X, 0, 6, 0, 0));
    b.emit(Insn::new(ADD_K, 0, 0, 0, 14));
    b.emit(Insn::new(ADD_X, 0, 9, 0, 0));
    b.jump(Insn::new(JGT_X, 0, 7, 0, 0), Label::Malformed);
    b.bound(34 + l4_min, Label::Malformed);
    match capture.protocol {
        Protocol::Tcp => {
            b.emit(Insn::new(LDX_B, 0, 6, 46, 0));
            b.emit(Insn::new(RSH_K, 0, 0, 0, 4));
            b.emit(Insn::new(LSH_K, 0, 0, 0, 2));
            b.jump(Insn::new(JLT_K, 0, 0, 0, 20), Label::Malformed);
            b.emit(Insn::new(ADD_K, 0, 0, 0, 20));
            b.jump(Insn::new(JGT_X, 0, 9, 0, 0), Label::Malformed);
        }
        Protocol::Udp => {
            b.emit(Insn::new(LDX_H, 0, 6, 38, 0));
            b.emit(Insn::new(BE16, 0, 0, 0, 16));
            b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
            b.emit(Insn::new(ADD_K, 1, 0, 0, -20));
            b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Malformed);
        }
    }
    for (offset, port) in [(34, capture.client.port()), (36, capture.service.port())] {
        b.emit(Insn::new(LDX_H, 0, 6, offset, 0));
        b.jump(
            Insn::new(JNE_K, 0, 0, 0, i32::from(port.to_be())),
            Label::Pass,
        );
    }
    for (offset, mac) in [(0, capture.own_mac), (6, capture.peer_mac)] {
        b.emit(Insn::new(LDX_W, 0, 6, offset, 0));
        b.jump(
            Insn::new(
                JNE32_K,
                0,
                0,
                0,
                u32::from_ne_bytes(mac[..4].try_into().unwrap()) as i32,
            ),
            Label::Malformed,
        );
        b.emit(Insn::new(LDX_H, 0, 6, offset + 4, 0));
        b.jump(
            Insn::new(
                JNE_K,
                0,
                0,
                0,
                i32::from(u16::from_ne_bytes([mac[4], mac[5]])),
            ),
            Label::Malformed,
        );
    }
    b.jump(Insn::new(JGE_K, 8, 0, 0, queues as i32), Label::Malformed);
    b.emit(Insn::new(STX_W, 10, 8, -4, 0));
    b.count(counters_fd);
    if data {
        b.map_fd(xsks_fd);
        b.emit(Insn::new(MOV_X, 2, 8, 0, 0));
        b.emit(Insn::new(MOV_K, 3, 0, 0, XDP_DROP));
        b.emit(Insn::new(CALL, 0, 0, 0, 51));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    } else {
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
    }
    for (label, key) in [
        (Label::Fragments, queues),
        (Label::Options, queues + 1),
        (Label::Malformed, queues + 2),
    ] {
        b.label(label);
        b.emit(Insn::new(ST_W, 10, 0, -4, key as i32));
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::CountDrop);
    }
    b.label(Label::CountDrop);
    b.count(counters_fd);
    b.label(Label::Drop);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_DROP));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.label(Label::Pass);
    b.emit(Insn::new(MOV_K, 0, 0, 0, XDP_PASS));
    b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }

    fn test_gate_with_program(program: OwnedFd) -> Arc<NativeTcxAttachment> {
        Arc::new(NativeTcxAttachment {
            program,
            root: test_fd(),
            ifindex: 23,
            program_id: 41,
            authority: honk_ebpf_common::xdp::CaptureAuthority {
                namespace_cookie: 17,
                attachment_generation: 19,
                scope: 29,
                config_generation: 31,
                ifindex: 23,
                reserved: 0,
            },
            pin: PathBuf::from("/private/native-gate-prog"),
            captured: Mutex::new(None),
        })
    }

    fn test_gate() -> Arc<NativeTcxAttachment> {
        test_gate_with_program(test_fd())
    }

    fn test_chain(program: Option<u32>, revision: u64) -> TcxChain {
        let mut chain = TcxChain {
            programs: [0; TCX_QUERY_CAPACITY],
            links: [0; TCX_QUERY_CAPACITY],
            count: usize::from(program.is_some()),
            revision,
        };
        chain.programs[0] = program.unwrap_or(0);
        chain
    }

    fn test_native_state() -> NativeXdp {
        NativeXdp {
            root: test_fd(),
            guard: test_fd(),
            data: test_fd(),
            guard_id: 7,
            data_id: 8,
            active: false,
            retired: None,
            pending: None,
            pin_ready: false,
            gate: None,
            updates: None,
        }
    }

    #[test]
    fn native_observation_failure_cannot_reject_an_acknowledged_selection() {
        use std::cell::Cell;
        for activate in [false, true] {
            let mut state = test_native_state();
            state.active = !activate;
            state.gate = Some(test_gate());
            let readback = Cell::new(false);
            let mut observation = Ok(());
            let update = |_, _| {
                let outcome = NativeUpdateOutcome {
                    transport: Ok(()),
                    observation: Err(invalid_data("ACK succeeded but own event was missing")),
                };
                observation = outcome.observation;
                outcome.transport.map_err(io::Error::from)
            };
            let result = if activate {
                state
                    .activate_with(
                        |_| Ok(()),
                        update,
                        |id| {
                            readback.set(true);
                            Ok(XdpState {
                                attached: 1,
                                prog_id: id,
                                drv_prog_id: id,
                                ..XdpState::default()
                            })
                        },
                    )
                    .map(|_| ())
            } else {
                state.guard_with(update, |_| {
                    readback.set(true);
                    Ok(())
                })
            };
            assert!(combine_observation(result, observation).is_err());
            assert!(readback.get());
            assert_eq!(state.active, activate);
            assert!(state.pending.is_none());
        }
        let mut state = test_native_state();
        state.active = true;
        let next = test_fd();
        let next_fd = next.as_raw_fd();
        let selected = state
            .publication_selection(next, Ok(()), |_| {
                panic!("post-ACK observation failure cannot discard an attached candidate")
            })
            .unwrap();
        state.retired = Some(std::mem::replace(&mut state.data, selected));
        state.data_id = 9;
        assert!(combine_observation(Ok(()), Err(invalid_data("post-ACK receive loss"))).is_err());
        assert_eq!(state.data.as_raw_fd(), next_fd);
        assert_eq!(state.selected_id(), 9);
        assert!(state.pending.is_none());
        assert!(state.retired.is_some());
    }

    #[test]
    fn native_terminal_cleanup_preserves_operation_and_observation_failures() {
        let result = combine_observation::<()>(
            Err(io::Error::other("guard readback failed")),
            Err(invalid_data("topology receive loss")),
        );
        let message = result.unwrap_err().to_string();
        assert!(message.contains("guard readback failed"));
        assert!(message.contains("topology receive loss"));
    }

    #[test]
    fn native_guard_observation_failures_still_withdraw_both_recording_hooks() {
        use std::cell::RefCell;
        for failed in [
            "strict precheck",
            "already invalidated",
            "post-ACK observation",
        ] {
            let calls = RefCell::new(Vec::new());
            let result = withdraw_recording_hooks_with(
                || {
                    calls.borrow_mut().push("guard");
                    Err(invalid_data(failed))
                },
                || {
                    calls.borrow_mut().push("TC withdrawal");
                    Ok(())
                },
                || {
                    calls.borrow_mut().push("query withdrawal");
                    Ok(())
                },
            );
            assert!(result.unwrap_err().to_string().contains(failed));
            assert_eq!(
                *calls.borrow(),
                ["guard", "TC withdrawal", "query withdrawal"]
            );
        }
        let result = withdraw_recording_hooks_with(
            || Err(invalid_data("guard failed")),
            || Err(invalid_data("TC withdrawal failed")),
            || Err(invalid_data("query withdrawal failed")),
        )
        .unwrap_err()
        .to_string();
        for expected in [
            "guard failed",
            "TC withdrawal failed",
            "query withdrawal failed",
        ] {
            assert!(result.contains(expected));
        }
    }

    #[test]
    fn native_gate_install_prepins_then_revision_fences_nonlink_attach() {
        use std::cell::{Cell, RefCell};
        let events = RefCell::new(Vec::new());
        let attached = Cell::new(false);
        let registered = RefCell::new(None);
        let gate = test_gate();
        let fd = gate.program.as_raw_fd() as u32;
        let result = install_native_gate_with(
            gate,
            |_| {
                events.borrow_mut().push("pin");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("pin-info");
                Ok(41)
            },
            |ifindex, direction| {
                assert_eq!(ifindex, 23);
                events.borrow_mut().push(if direction == BPF_TCX_INGRESS {
                    "ingress"
                } else {
                    "egress"
                });
                Ok(test_chain(
                    (attached.get() && direction == BPF_TCX_INGRESS).then_some(41),
                    if attached.get() && direction == BPF_TCX_INGRESS {
                        10
                    } else {
                        9
                    },
                ))
            },
            |command, attr| {
                events.borrow_mut().push("attach");
                assert_eq!(command, BPF_PROG_ATTACH);
                assert_eq!(
                    (attr.target_ifindex, attr.attach_bpf_fd, attr.attach_type),
                    (23, fd, BPF_TCX_INGRESS)
                );
                assert_eq!(
                    (
                        attr.attach_flags,
                        attr.replace_bpf_fd,
                        attr.relative_fd,
                        attr.expected_revision
                    ),
                    (0, 0, 0, 9)
                );
                attached.set(true);
                Ok(())
            },
            |owner| {
                events.borrow_mut().push("register");
                *registered.borrow_mut() = Some(owner);
                Ok(())
            },
        )
        .unwrap();
        assert!(Arc::ptr_eq(registered.borrow().as_ref().unwrap(), &result));
        assert_eq!(
            *events.borrow(),
            [
                "pin", "pin-info", "ingress", "egress", "attach", "ingress", "egress", "pin-info",
                "register"
            ]
        );
        assert_eq!(size_of::<TcxAttachAttr>(), 32);
        assert_eq!(std::mem::offset_of!(TcxAttachAttr, expected_revision), 24);
        assert_eq!(size_of::<TcxQueryAttr>(), 64);
        assert_eq!(std::mem::offset_of!(TcxQueryAttr, prog_ids), 16);
        assert_eq!(std::mem::offset_of!(TcxQueryAttr, link_ids), 40);
        assert_eq!(std::mem::offset_of!(TcxQueryAttr, revision), 56);
    }

    #[test]
    fn native_gate_install_errors_retain_pins_without_leaking_program_fd() {
        use std::cell::Cell;
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        for failure in [
            "pin",
            "pre-info",
            "attach",
            "query",
            "post-info",
            "register",
        ] {
            let (program, mut peer) = UnixStream::pair().unwrap();
            peer.set_nonblocking(true).unwrap();
            let owner = test_gate_with_program(program.into());
            let weak = Arc::downgrade(&owner);
            let pinned = Cell::new(false);
            let attached = Cell::new(false);
            let mutations = Cell::new(0);
            let registrations = Cell::new(0);
            let failed = || io::Error::from_raw_os_error(libc::EIO);
            let result = install_native_gate_with(
                owner,
                |_| {
                    assert!(!attached.get());
                    if failure == "pin" {
                        return Err(failed());
                    }
                    pinned.set(true);
                    Ok(())
                },
                |_| {
                    let phase = if attached.get() {
                        "post-info"
                    } else {
                        "pre-info"
                    };
                    if failure == phase {
                        return Err(failed());
                    }
                    Ok(41)
                },
                |_, direction| {
                    if attached.get() && failure == "query" {
                        return Err(failed());
                    }
                    Ok(test_chain(
                        (attached.get() && direction == BPF_TCX_INGRESS).then_some(41),
                        if attached.get() { 10 } else { 9 },
                    ))
                },
                |command, _| {
                    assert_eq!(
                        command, BPF_PROG_ATTACH,
                        "failure must never detach or fall back to a link"
                    );
                    mutations.set(mutations.get() + 1);
                    if failure == "attach" {
                        return Err(failed());
                    }
                    attached.set(true);
                    Ok(())
                },
                |_| {
                    registrations.set(registrations.get() + 1);
                    Err(failed())
                },
            );
            assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EIO));
            assert_eq!(pinned.get(), failure != "pin");
            assert_eq!(
                mutations.get(),
                usize::from(!matches!(failure, "pin" | "pre-info"))
            );
            assert_eq!(
                attached.get(),
                matches!(failure, "query" | "post-info" | "register")
            );
            assert_eq!(registrations.get(), usize::from(failure == "register"));
            assert!(weak.upgrade().is_none());
            assert_eq!(
                peer.read(&mut [0]).unwrap(),
                0,
                "ordinary RAII must close the program FD"
            );
        }
    }

    #[test]
    fn native_gate_checks_precede_activation_and_both_publication_updates() {
        use std::cell::Cell;
        for condition in ["missing", "conflict", "valid"] {
            let mut state = test_native_state();
            if condition != "missing" {
                let owner = test_gate();
                state.register_gate(Arc::clone(&owner)).unwrap();
                assert!(Arc::ptr_eq(state.gate.as_ref().unwrap(), &owner));
                assert!(state.register_gate(owner).is_err());
            }
            let check = |owner: &NativeTcxAttachment| {
                owner.check_with(
                    17,
                    41,
                    &test_chain(Some(if condition == "conflict" { 42 } else { 41 }), 200),
                    &test_chain(None, 1),
                )
            };
            let updates = Cell::new(0);
            let result = state.activate_with(
                check,
                |_, _| {
                    updates.set(updates.get() + 1);
                    Ok(())
                },
                |id| {
                    Ok(XdpState {
                        prog_id: id,
                        ..XdpState::default()
                    })
                },
            );
            assert_eq!(result.is_ok(), condition == "valid");
            assert_eq!(updates.get(), usize::from(condition == "valid"));
            for boundary in ["xdp-selection", "tc-slot"] {
                let called = Cell::new(false);
                let result = state.publish_with(check, |_| {
                    called.set(true);
                    Ok(boundary)
                });
                assert_eq!(result.is_ok(), condition == "valid");
                assert_eq!(called.get(), condition == "valid");
            }
            state.active = true;
            let guard_called = Cell::new(false);
            state
                .guard_with(
                    |_, _| {
                        guard_called.set(true);
                        Ok(())
                    },
                    |_| Ok(()),
                )
                .unwrap();
            assert!(guard_called.get());
            assert!(!state.active);
        }
    }

    #[test]
    fn native_gate_identity_and_complete_query_reject_foreign_or_partial_state() {
        let owner = test_gate();
        let ingress = test_chain(Some(41), 12);
        let egress = test_chain(None, 1);
        owner.check_with(17, 41, &ingress, &egress).unwrap();
        owner
            .check_with(17, 41, &test_chain(Some(41), 99), &egress)
            .unwrap();
        assert!(owner.check_with(18, 41, &ingress, &egress).is_err());
        assert!(owner.check_with(17, 42, &ingress, &egress).is_err());
        for mut bad in [
            test_chain(None, 1),
            test_chain(Some(42), 12),
            test_chain(Some(41), 0),
        ] {
            assert!(owner.check_with(17, 41, &bad, &egress).is_err());
            bad.count = 2;
            assert!(owner.check_with(17, 41, &bad, &egress).is_err());
        }
        let mut linked = ingress.clone();
        linked.links[0] = 91;
        assert!(owner.check_with(17, 41, &linked, &egress).is_err());
        assert!(owner.check_with(17, 41, &ingress, &ingress).is_err());
        let mut wrong_device = test_gate();
        Arc::get_mut(&mut wrong_device).unwrap().ifindex = 24;
        assert!(wrong_device.check_with(17, 41, &ingress, &egress).is_err());
        validate_pinned_program(
            &ProgInfo {
                kind: BPF_PROG_TYPE_SCHED_CLS,
                id: 41,
            },
            BPF_PROG_TYPE_SCHED_CLS,
        )
        .unwrap();
        for info in [
            ProgInfo {
                kind: BPF_PROG_TYPE_XDP,
                id: 41,
            },
            ProgInfo { kind: 11, id: 41 },
            ProgInfo {
                kind: BPF_PROG_TYPE_SCHED_CLS,
                id: 0,
            },
        ] {
            assert!(validate_pinned_program(&info, BPF_PROG_TYPE_SCHED_CLS).is_err());
        }
        for case in [
            "valid",
            "overflow",
            "short",
            "missing-link",
            "flags",
            "zero-revision",
            "enospc",
        ] {
            let result = query_tcx_with(23, BPF_TCX_INGRESS, |command, attr| {
                assert_eq!(command, BPF_PROG_QUERY);
                assert_eq!(
                    (attr.target_ifindex, attr.attach_type, attr.query_flags),
                    (23, BPF_TCX_INGRESS, 0)
                );
                assert_ne!(attr.prog_ids, 0);
                assert_ne!(attr.link_ids, 0);
                assert_eq!(attr.count, TCX_QUERY_CAPACITY as u32);
                if case == "enospc" {
                    return Err(io::Error::from_raw_os_error(libc::ENOSPC));
                }
                attr.count = if case == "overflow" {
                    TCX_QUERY_CAPACITY as u32 + 1
                } else {
                    1
                };
                attr.revision = if case == "zero-revision" { 0 } else { 12 };
                if case != "short" {
                    // SAFETY: query_tcx_with keeps all four fixed buffers alive for this callback.
                    unsafe {
                        *(attr.prog_ids as *mut u32) = 41;
                        if case != "missing-link" {
                            *(attr.link_ids as *mut u32) = 0;
                        }
                        *(attr.prog_attach_flags as *mut u32) = if case == "flags" { 1 } else { 0 };
                        *(attr.link_attach_flags as *mut u32) = 0;
                    }
                }
                Ok(())
            });
            assert_eq!(result.is_ok(), case == "valid");
            if case == "enospc" {
                assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::ENOSPC));
            }
        }
    }

    #[test]
    fn native_gate_exact_detach_retains_nonzero_fd_through_readback() {
        use std::cell::Cell;
        const CHILD: &str = "HONK_NATIVE_GATE_FD_ZERO_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bpf::tests::native_gate_exact_detach_retains_nonzero_fd_through_readback",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            return;
        }
        let (program, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let original: OwnedFd = program.into();
        // SAFETY: this isolated test child owns its stdin and replaces it with this live FD.
        assert_eq!(unsafe { libc::dup2(original.as_raw_fd(), 0) }, 0);
        // SAFETY: stdin remains a live descriptor until this child exits.
        let zero = unsafe { BorrowedFd::borrow_raw(0) };
        let copied = Cell::new(-1);
        tcx_mutate_with(
            BPF_PROG_DETACH,
            zero,
            23,
            53,
            duplicate_nonzero_fd,
            |command, attr| {
                assert_eq!(command, BPF_PROG_DETACH);
                assert!(attr.attach_bpf_fd > 0);
                copied.set(attr.attach_bpf_fd as RawFd);
                // SAFETY: copied names the retained live descriptor passed to this syscall seam.
                let retained = unsafe { BorrowedFd::borrow_raw(copied.get()) };
                assert_eq!(
                    directory_identity(zero).unwrap(),
                    directory_identity(retained).unwrap()
                );
                assert_eq!(
                    (
                        attr.target_ifindex,
                        attr.attach_type,
                        attr.attach_flags,
                        attr.replace_bpf_fd,
                        attr.relative_fd,
                        attr.expected_revision
                    ),
                    (23, BPF_TCX_INGRESS, 0, 0, 0, 53)
                );
                Ok(())
            },
            || {
                // SAFETY: the production seam must retain its duplicate throughout readback.
                assert!(unsafe { libc::fcntl(copied.get(), libc::F_GETFD) } >= 0);
                Ok(())
            },
        )
        .unwrap();
        // SAFETY: F_GETFD only inspects whether the duplicate is still live.
        assert_eq!(unsafe { libc::fcntl(copied.get(), libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        let result = tcx_mutate_with(
            BPF_PROG_DETACH,
            zero,
            23,
            53,
            |_| Err(io::Error::from_raw_os_error(libc::EMFILE)),
            |_, _| panic!("duplication failure must send zero detach requests"),
            || panic!("duplication failure cannot claim absence"),
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EMFILE));
        let result = tcx_mutate_with(
            BPF_PROG_DETACH,
            original.as_fd(),
            23,
            52,
            |_| panic!("nonzero exact FD must be retained directly"),
            |command, attr| {
                assert_eq!(
                    (command, attr.attach_bpf_fd, attr.expected_revision),
                    (BPF_PROG_DETACH, original.as_raw_fd() as u32, 52)
                );
                Err(io::Error::from_raw_os_error(libc::ESTALE))
            },
            || panic!("stale detach must not requery, unlink or report absence"),
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ESTALE));
        assert!(
            tcx_mutate_with(
                BPF_PROG_DETACH,
                zero,
                23,
                0,
                |_| panic!("zero revision must fail before duplication"),
                |_, _| panic!("zero revision must never send an unfenced detach"),
                || panic!("invalid request cannot claim absence")
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_instruction_storage_exceeds_wrapper_capacity_without_panicking() {
        let mut builder = Builder::new();
        builder.reserve(5000).unwrap();
        for _ in 0..5000 {
            builder.emit(Insn::new(MOV_K, 0, 0, 0, 0));
        }
        assert_eq!(builder.program.len, 5000);
        assert_eq!(builder.program.insns.len(), 5000);
        let before = builder.program.len;
        assert_eq!(
            builder.reserve(MAX_PROGRAM_INSNS).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(builder.program.len, before);
    }

    #[test]
    fn native_guard_uses_replacement_data_fd() {
        let fd = || -> OwnedFd { std::fs::File::open("/dev/null").unwrap().into() };
        let mut state = NativeXdp {
            root: fd(),
            guard: fd(),
            data: fd(),
            guard_id: 7,
            data_id: 8,
            active: true,
            retired: None,
            pending: None,
            pin_ready: false,
            gate: None,
            updates: None,
        };
        let replacement = fd();
        let replacement_fd = replacement.as_raw_fd();
        state.retired = Some(std::mem::replace(&mut state.data, replacement));
        state.data_id = 9;
        let guard_fd = state.guard.as_raw_fd();
        let retired_fd = state.retired.as_ref().unwrap().as_raw_fd();
        for error in [
            io::Error::from_raw_os_error(libc::EEXIST),
            io::Error::new(io::ErrorKind::TimedOut, "uncertain update"),
        ] {
            assert!(
                state
                    .guard_with(
                        |new, expected_old| {
                            assert_eq!((new, expected_old), (guard_fd, replacement_fd));
                            Err(error)
                        },
                        |_| panic!("failed update cannot claim readback")
                    )
                    .is_err()
            );
            assert!(state.active);
            assert_eq!(state.selected_id(), 9);
            assert_eq!(state.retired.as_ref().unwrap().as_raw_fd(), retired_fd);
        }
        state
            .guard_with(
                |new, expected_old| {
                    assert_eq!(new, guard_fd);
                    assert_eq!(expected_old, replacement_fd);
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
        assert!(!state.active);
        assert_eq!(state.selected_id(), 7);
        assert_eq!(state.data_id, 9);
        assert!(
            state.retired.is_some(),
            "guarding cannot retire the pre-grace data owner"
        );
    }

    #[test]
    fn native_acknowledged_selection_survives_guard_and_activate_readback_failure() {
        let fd = || -> OwnedFd { std::fs::File::open("/dev/null").unwrap().into() };
        let mut state = NativeXdp {
            root: fd(),
            guard: fd(),
            data: fd(),
            guard_id: 7,
            data_id: 9,
            active: true,
            retired: Some(fd()),
            pending: None,
            pin_ready: false,
            gate: Some(test_gate()),
            updates: None,
        };
        let guard = state.guard.as_raw_fd();
        let data = state.data.as_raw_fd();
        let retired = state.retired.as_ref().unwrap().as_raw_fd();
        let failed_readback = |id| {
            assert_eq!(id, 7);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guard readback failed",
            ))
        };
        assert!(
            state
                .guard_with(
                    |new, old| {
                        assert_eq!((new, old), (guard, data));
                        Ok(())
                    },
                    failed_readback
                )
                .is_err()
        );
        assert!(!state.active);
        assert_eq!(state.selected_id(), 7);
        assert_eq!(state.retired.as_ref().unwrap().as_raw_fd(), retired);
        state
            .guard_with(
                |_, _| panic!("ACKed guard must not update again"),
                |id| {
                    assert_eq!(id, 7);
                    Ok(())
                },
            )
            .unwrap();
        assert!(
            state
                .activate_with(
                    |_| Ok(()),
                    |new, old| {
                        assert_eq!((new, old), (data, guard));
                        Ok(())
                    },
                    |id| {
                        assert_eq!(id, 9);
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "data readback failed",
                        ))
                    }
                )
                .is_err()
        );
        assert!(state.active);
        assert_eq!(state.selected_id(), 9);
        assert_eq!(state.data.as_raw_fd(), data);
        assert_eq!(state.retired.as_ref().unwrap().as_raw_fd(), retired);
        let confirmed = state
            .activate_with(
                |_| Ok(()),
                |_, _| panic!("ACKed data must not update again"),
                |id| {
                    assert_eq!(id, 9);
                    Ok(XdpState {
                        attached: 1,
                        prog_id: id,
                        drv_prog_id: id,
                        ..XdpState::default()
                    })
                },
            )
            .unwrap();
        assert_eq!(confirmed.prog_id, 9);
    }

    #[test]
    fn native_unattempted_activation_preserves_guard_data_and_pending_owners() {
        let mut state = test_native_state();
        state.gate = Some(test_gate());
        let guard = state.guard.as_raw_fd();
        let data = state.data.as_raw_fd();
        let result = state.activate_with(
            |_| Ok(()),
            |_, _| {
                Err(XdpUpdateError::NotAttempted(invalid_data(
                    "watch refused data activation before SETLINK",
                ))
                .into())
            },
            |_| panic!("unattempted activation cannot claim selected-data readback"),
        );
        assert!(result.is_err());
        assert!(!state.active);
        assert_eq!(state.selected_id(), 7);
        assert_eq!(state.guard.as_raw_fd(), guard);
        assert_eq!(state.data.as_raw_fd(), data);
        assert!(state.pending.is_none());
        assert!(state.retired.is_none());
        assert!(!state.pin_ready);
    }

    #[test]
    fn native_unattempted_publication_discards_only_verified_staging() {
        for verified in [false, true] {
            let mut state = test_native_state();
            state.active = true;
            let prior = state.data.as_raw_fd();
            let next = test_fd();
            let candidate = next.as_raw_fd();
            let result = state.publication_selection(
                next,
                Err(XdpUpdateError::NotAttempted(invalid_data(
                    "sticky watch refused update",
                ))),
                |_| {
                    if verified {
                        Ok(())
                    } else {
                        Err(invalid_data("staging identity changed"))
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(state.data.as_raw_fd(), prior);
            assert_eq!(state.data_id, 8);
            assert_eq!(state.pending.is_none(), verified);
            if !verified {
                assert_eq!(state.pending.as_ref().unwrap().as_raw_fd(), candidate);
            }
        }
    }

    #[test]
    fn native_publication_uncertainty_retains_staged_candidate_and_old_owner() {
        let fd = || -> OwnedFd { std::fs::File::open("/dev/null").unwrap().into() };
        for (rejected, identity_matches) in [(false, true), (true, true), (true, false)] {
            let mut state = NativeXdp {
                root: fd(),
                guard: fd(),
                data: fd(),
                guard_id: 7,
                data_id: 8,
                active: true,
                retired: None,
                pending: None,
                pin_ready: false,
                gate: None,
                updates: None,
            };
            let old = state.data.as_raw_fd();
            let next = fd();
            let candidate = next.as_raw_fd();
            let staged = std::cell::Cell::new(true);
            let result = Err(if rejected {
                XdpUpdateError::Rejected(io::Error::from_raw_os_error(libc::EEXIST))
            } else {
                XdpUpdateError::Uncertain(io::Error::new(io::ErrorKind::TimedOut, "missing ACK"))
            });
            let error = state
                .publication_selection(next, result, |_| {
                    assert!(rejected, "uncertain completion cannot unlink data-next");
                    if !identity_matches {
                        return Err(invalid_data("prior attachment or staging identity changed"));
                    }
                    staged.set(false);
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(state.data.as_raw_fd(), old);
            assert_eq!(state.data_id, 8);
            assert!(state.active);
            assert!(!state.pin_ready);
            assert_eq!(staged.get(), !rejected || !identity_matches);
            if rejected && identity_matches {
                assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
                assert!(state.pending.is_none());
                assert!(state.require_resolved().is_ok());
            } else {
                assert_eq!(state.pending.as_ref().unwrap().as_raw_fd(), candidate);
                assert!(state.require_resolved().is_err());
                assert!(state.finish_publication().is_err());
                assert_eq!(state.data.as_raw_fd(), old);
                assert_eq!(state.pending.as_ref().unwrap().as_raw_fd(), candidate);
            }
        }
    }

    fn capture(protocol: Protocol) -> Capture {
        Capture {
            protocol,
            client: "10.10.10.251:41000".parse().unwrap(),
            service: "10.10.10.252:42000".parse().unwrap(),
            own_mac: [0x58, 0x47, 0xca, 0x74, 0xec, 0x9d],
            peer_mac: [0xba, 0xda, 0x2e, 0x00, 0x76, 0xa0],
        }
    }

    #[test]
    fn program_builder_rejects_invalid_queue_domains() {
        assert!(build_program(&capture(Protocol::Udp), 0, 10, 11, true).is_err());
        assert!(build_program(&capture(Protocol::Udp), 257, 10, 11, true).is_err());
        let mut unresolved = Builder::new();
        unresolved.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
        assert!(unresolved.finish().is_err());
    }

    #[test]
    fn persistent_pin_preflight_rejects_ordinary_filesystem_without_writes() {
        let error = private_bpffs(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "XDP pin root must be bpffs");
    }

    #[test]
    fn persistent_updates_encode_native_exclusion_and_kernel_comparison() {
        for (program, expected) in [(12, None), (12, Some(11)), (-1, Some(11)), (-1, Some(-2))] {
            let (request, length) = xdp_update_request(7, program, expected);
            assert_eq!(
                u32::from_ne_bytes(request[..4].try_into().unwrap()) as usize,
                length,
            );
            assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), 19);
            assert_eq!(u16::from_ne_bytes(request[6..8].try_into().unwrap()), 5);
            assert_eq!(i32::from_ne_bytes(request[20..24].try_into().unwrap()), 7);
            let mut outer = 0;
            attributes(&request[32..length], |kind, value| {
                outer += 1;
                assert_eq!(kind, 43);
                let mut fields = Vec::new();
                attributes(value, |kind, value| {
                    fields.push((kind, i32::from_ne_bytes(value.try_into().unwrap())));
                    Ok(())
                })?;
                assert_eq!(fields[0], (1, program));
                assert_eq!(fields[1], (3, if expected.is_some() { 20 } else { 5 }));
                if let Some(expected) = expected {
                    assert_eq!(fields, [(1, program), (3, 20), (8, expected)]);
                } else {
                    assert_eq!(fields, [(1, program), (3, 5)]);
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(outer, 1);
        }
        let native = XdpState {
            attached: 1,
            prog_id: 12,
            drv_prog_id: 12,
            ..XdpState::default()
        };
        assert!(require_native(native, 12).is_ok());
        for foreign in [
            XdpState {
                prog_id: 13,
                ..native
            },
            XdpState {
                skb_prog_id: 13,
                ..native
            },
            XdpState {
                hw_prog_id: 13,
                ..native
            },
            XdpState {
                attached: 2,
                drv_prog_id: 0,
                skb_prog_id: 12,
                ..native
            },
            XdpState {
                drv_prog_id: 13,
                ..native
            },
            XdpState {
                attached: 3,
                drv_prog_id: 0,
                hw_prog_id: 12,
                ..native
            },
            XdpState {
                attached: 4,
                ..native
            },
            XdpState::default(),
        ] {
            assert!(require_native(foreign, 12).is_err());
        }
    }

    #[test]
    fn queued_kernel_setlink_ack_survives_an_expired_send_deadline() {
        // No interface index or name: the kernel must reject this without touching a link.
        let (request, length) = xdp_update_request(0, -1, Some(-1));
        // SAFETY: socket has scalar arguments and returns a unique owned descriptor.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: the request and kernel address remain live during the synchronous send.
        assert_eq!(
            unsafe {
                libc::sendto(
                    raw,
                    request.as_ptr().cast(),
                    length,
                    0,
                    std::ptr::from_ref(&kernel).cast(),
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            },
            length as isize
        );
        let deadline = Instant::now() - Duration::from_secs(1);
        wait_netlink(fd.as_fd(), libc::POLLIN, deadline).unwrap();
        let mut reply = [0u8; 512];
        // SAFETY: reply is writable for its whole extent; no sender address is requested.
        let received = unsafe {
            libc::recv(
                raw,
                reply.as_mut_ptr().cast(),
                reply.len(),
                libc::MSG_DONTWAIT,
            )
        };
        assert!(received >= 20);
        let error = parse_setlink_ack(&reply[..received as usize], 1).unwrap_err();
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::EINVAL | libc::EPERM)
        ));
        assert_eq!(
            wait_netlink(fd.as_fd(), libc::POLLIN, deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            wait_netlink(fd.as_fd(), libc::POLLOUT, deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn persistent_updates_require_successful_matching_kernel_ack() {
        let (request, _) = xdp_update_request(7, -1, Some(11));
        let mut ack = [0u8; 36];
        ack[..4].copy_from_slice(&36u32.to_ne_bytes());
        ack[20..36].copy_from_slice(&request[..16]);
        ack[4..6].copy_from_slice(&2u16.to_ne_bytes());
        ack[8..12].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(parse_setlink_ack(&ack, 1).unwrap(), Some(()));
        assert_eq!(parse_setlink_ack(&ack, 2).unwrap(), None);
        for end in 1..ack.len() {
            assert!(parse_setlink_ack(&ack[..end], 1).is_err());
        }
        let mut incomplete = ack;
        incomplete[..4].copy_from_slice(&20u32.to_ne_bytes());
        assert!(parse_setlink_ack(&incomplete[..20], 1).is_err());
        let mut wrong_request = ack;
        wrong_request[28..32].copy_from_slice(&2u32.to_ne_bytes());
        assert!(parse_setlink_ack(&wrong_request, 1).is_err());
        for errno in [libc::EEXIST, libc::EBUSY, libc::EINVAL, libc::EOPNOTSUPP] {
            ack[16..20].copy_from_slice(&(-errno).to_ne_bytes());
            assert_eq!(
                parse_setlink_ack(&ack, 1).unwrap_err().raw_os_error(),
                Some(errno),
            );
        }
    }

    fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let length = 4 + value.len();
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
    }

    #[test]
    fn netlink_readback_checks_nested_extents_and_native_identity() {
        let mut nested = Vec::new();
        attribute(&mut nested, 2, &[1]);
        attribute(&mut nested, 3, &4u32.to_ne_bytes());
        attribute(&mut nested, 4, &123u32.to_ne_bytes());
        attribute(&mut nested, 5, &123u32.to_ne_bytes());
        let mut reply = vec![0; 32];
        reply[4..6].copy_from_slice(&16u16.to_ne_bytes());
        reply[8..12].copy_from_slice(&1u32.to_ne_bytes());
        reply[20..24].copy_from_slice(&7i32.to_ne_bytes());
        attribute(&mut reply, 43 | 0x8000, &nested);
        let length = reply.len() as u32;
        reply[..4].copy_from_slice(&length.to_ne_bytes());
        let state = parse_link_messages(&reply, 1, 7).unwrap().unwrap();
        assert_eq!(require_native(state, 123).unwrap().flags, 4);
        assert!(require_native(state, 124).is_err());
        assert!(parse_link_messages(&reply, 2, 7).unwrap().is_none());
        assert!(parse_link_messages(&reply, 1, 8).unwrap().is_none());
        for end in 1..reply.len() {
            assert!(parse_link_messages(&reply[..end], 1, 7).is_err());
        }
        for bad in [
            &[3, 0, 2, 0][..],
            &[8, 0, 4, 0, 1][..],
            &[5, 0, 4, 0, 1][..],
        ] {
            assert!(parse_xdp_attributes(bad).is_err());
        }
        assert_eq!(size_of::<MapElemAttr>(), 32);
        assert_eq!(size_of::<ProgLoadAttr>(), 128);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, attach_btf_id), 108);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, attach_prog_fd), 112);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, core_relo_cnt), 116);
        assert_eq!(std::mem::offset_of!(ProgLoadAttr, fd_array), 120);
        assert_eq!(size_of::<LinkCreateAttr>(), 16);
        assert_eq!(size_of::<LinkUpdateAttr>(), 16);
        assert_eq!(std::mem::offset_of!(LinkInfo, ifindex), 16);
    }
}
