//! Original LOCAL_OUT consumers. The source selector remains owned by the parent.
use super::*;
use honk_ebpf_common::xdp::{
    NATIVE_DOMAIN_FLOW, NATIVE_DOMAIN_SOURCE, NATIVE_DOMAIN_UNBOUND_SOURCE,
    NATIVE_EXECUTOR_CAPTURE, NATIVE_EXECUTOR_KERNEL, NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_ACTIVE,
    NATIVE_PHASE_ARMED, NATIVE_PHASE_CAPTURE_COMMITTED, NATIVE_PHASE_SOURCE_PENDING,
    NATIVE_ZONE_BOUND_ACTUAL, NativeClaim, NativeScratch,
};
use honk_ebpf_common::{
    DATAPATH_FLAG_OFFLOAD_ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT, IpVersionType, KernelRouteOutput,
    L4ProtoType, ROUTING_INPUT_ALLOW_DIRECT_FINALITY, ROUTING_MARK_KEEP, ROUTING_MARK_SET,
    RoutingDecision, RoutingInput,
};

const NKEY: i16 = -496;
const NSCRATCH: i16 = -408;
const LENGTH: i16 = -412;
const ETHER: i16 = -416;
const CHOICE: i16 = -420;
const ROOT_POINTER: i16 = -432;
const OPEN_EPOCH: i16 = -440;
const MARK_KIND: i16 = M;
const MARK_VALUE: i16 = M + 4;
const RETAINED: i16 = M + 8;
const NET: i16 = M + 16;
const DATA: i16 = M + 24;
const TRANSITION: i16 = M + 80;
const SOURCE_INSERTED: i16 = M + 84;
const PENDING_RESERVED: i16 = M + 88;
const SOURCE_SOCKET: i16 = M + 96;
const SAVED_BANK: i16 = M + 112;
const LINEAR: i16 = M + 120;
const S_INPUT: i16 = std::mem::offset_of!(NativeScratch, input) as i16;
const S_OUTPUT: i16 = std::mem::offset_of!(NativeScratch, output) as i16;
const S_BUSY: i16 = std::mem::offset_of!(NativeScratch, busy) as i16;
const VALUE: i16 = S_INPUT + 56;
const CANONICAL_CALL: i32 = i32::MIN;
const PROGRAM_LIMIT: usize = 1 << 20;
const PROGRAM_PARTITION: usize = 16 << 20;
const WRAPPER_INSNS: usize = 12_288;
const MAX_ACTIONS: usize = 257;
const LOCAL_OUT: u32 = 3;
const NETFILTER: u32 = 32;
const NETFILTER_ATTACH: u32 = 45;

const JEQ32_K: u8 = 0x16;

const _: () = {
    assert!(NKEY >= -512 && NKEY + 56 <= OPEN_EPOCH);
    assert!(VALUE + 72 <= S_INPUT + size_of::<RoutingInput>() as i16);
};

/// Fields come from the same admitted running-kernel BTF as `HostSourceConfig`.
/// CT offsets address the actual `nf_conn`, not a lookup reconstructed from its tuple.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostNativeLayout {
    pub cast: u32,
    pub sock_cookie: u32,
    pub sock_family: u32,
    pub sock_state: u32,
    pub sock_type: u32,
    pub sock_protocol: u32,
    pub sock_mark: u32,
    pub skb_len: u32,
    pub skb_data_len: u32,
    pub skb_data: u32,
    pub skb_protocol: u32,
    pub skb_mark: u32,
    pub skb_refdst: u32,
    pub skb_nfct: u32,
    pub dst_dev: u32,
    pub dev_ifindex: u32,
    pub dev_net: u32,
    pub state_net: u32,
    pub state_out: u32,
    pub state_hook: u32,
    pub state_pf: u32,
    pub ct_net: u32,
    pub ct_status: u32,
    pub ct_zone_id: u32,
    pub ct_zone_dir: u32,
    pub ct_zone_flags: u32,
    pub ct_src: u32,
    pub ct_dst: u32,
    pub ct_sport: u32,
    pub ct_dport: u32,
    pub ct_family: u32,
    pub ct_protocol: u32,
    pub net_hooks_ipv4: u32,
    pub net_hooks_ipv6: u32,
    pub hooks_count: u32,
    pub hooks_entries: u32,
    pub hook_stride: u32,
    pub hook_callback: u32,
    pub hook_private: u32,
    pub prog_aux: u32,
    pub aux_id: u32,
    pub producer_callback: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct HostNativeConfig {
    pub source: HostSourceConfig,
    pub layout: HostNativeLayout,
    pub family: u8,
    pub scope: u64,
}

pub struct HostNativeLayoutAdmission {
    layout: HostNativeLayout,
    _module_btf: Option<OwnedFd>,
}

impl HostNativeLayoutAdmission {
    pub(in crate::bpf) fn from_admitted(
        layout: HostNativeLayout,
        module_btf: Option<OwnedFd>,
    ) -> Self {
        Self {
            layout,
            _module_btf: module_btf,
        }
    }
    pub fn layout(&self) -> HostNativeLayout {
        self.layout
    }
}

#[derive(Clone, Copy)]
pub struct HostNativeMaps<'a> {
    pub root: BorrowedFd<'a>,
    pub claims: BorrowedFd<'a>,
    pub scratch: BorrowedFd<'a>,
    pub gate: BorrowedFd<'a>,
    pub sequence: BorrowedFd<'a>,
    pub sockets: BorrowedFd<'a>,
    pub socket_locks: BorrowedFd<'a>,
    pub returns: BorrowedFd<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostNativeHook {
    pub family: u8,
    pub hook: u32,
    pub priority: i32,
    pub flags: u32,
    pub program_id: u32,
    pub link_id: u32,
}

struct Loaded {
    fd: OwnedFd,
    id: u32,
    memory: usize,
}

/// The producer link is never pinned, cloned, or exposed as an FD.
/// Persistent nft matchers check this program's actual current registration.
pub struct HostNativePrograms {
    config: HostNativeConfig,
    root: OwnedFd,
    claims: OwnedFd,
    scratch: OwnedFd,
    gate: OwnedFd,
    sequence: OwnedFd,
    sockets: OwnedFd,
    socket_locks: OwnedFd,
    returns: OwnedFd,
    dispatch: OwnedFd,
    producer: Loaded,
    binding: Loaded,
    producer_link: OwnedFd,
    binding_link: OwnedFd,
    hooks: [HostNativeHook; 2],
    _layout_admission: HostNativeLayoutAdmission,
}

pub struct HostNativeCandidate {
    selector: Loaded,
    actions: Vec<(Option<u32>, Loaded)>,
    candidate_scope: Loaded,
    root_id: u32,
    dispatch_id: u32,
    pub epoch: u64,
    pub scope: u64,
    pub expires_boottime_ns: u64,
    memory: usize,
}

impl HostNativeCandidate {
    pub fn actions(&self) -> impl ExactSizeIterator<Item = (Option<u32>, BorrowedFd<'_>, u32)> {
        self.actions
            .iter()
            .map(|(mark, p)| (*mark, p.fd.as_fd(), p.id))
    }
    pub fn candidate_scope(&self) -> (BorrowedFd<'_>, u32) {
        (self.candidate_scope.fd.as_fd(), self.candidate_scope.id)
    }
    pub fn selector_id(&self) -> u32 {
        self.selector.id
    }
    pub fn memory_bytes(&self) -> usize {
        self.memory
    }
}

impl HostNativePrograms {
    pub fn load_closed(
        config: &HostNativeConfig,
        btf: &Btf,
        maps: HostNativeMaps<'_>,
        admission: HostNativeLayoutAdmission,
    ) -> io::Result<Self> {
        if config.layout != admission.layout {
            return Err(invalid_data(
                "Host layout differs from actual BTF admission",
            ));
        }
        validate_config(config, btf)?;
        require_closed(maps.root)?;
        map_shape(maps.root, 2, size_of::<NativeRoot>() as u32, 1, 0)?;
        map_shape(maps.gate, 2, 4, 1, 0)?;
        map_shape(maps.sequence, 2, 16, 1, 0)?;
        map_shape(maps.sockets, 2, 520, HOST_SOCKET_BUCKETS as u32, 1024)?;
        map_shape(maps.socket_locks, 2, 8, HOST_SOCKET_BUCKETS as u32, 0)?;
        map_shape(maps.returns, 1, 32, 64, 0)?;
        admit_map(
            maps.claims,
            1,
            size_of::<NativeKey>() as u32,
            size_of::<NativeClaim>() as u32,
        )?;
        admit_map(maps.scratch, 2, 4, size_of::<NativeScratch>() as u32)?;
        let dispatch = create_map(3, 4, 1, b"honk_hn_disp")?;
        let mut log = vec![0; PROGRAM_LIMIT];
        let mut b = Builder::new();
        b.emit(Insn::new(MOV_X, 6, 1, 0, 0));
        b.map_fd(dispatch.as_raw_fd());
        b.emit(Insn::new(MOV_X, 2, 1, 0, 0));
        b.emit(Insn::new(MOV_X, 1, 6, 0, 0));
        b.emit(Insn::new(MOV_K, 3, 0, 0, 0));
        b.emit(Insn::new(CALL, 0, 0, 0, 12));
        b.emit(Insn::new(MOV_K, 0, 0, 0, 1));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        let producer = load(
            &b.finish()?,
            b"honk_hn_live",
            NETFILTER,
            NETFILTER_ATTACH,
            &mut log,
        )?;
        let selection = Selection {
            owner: config,
            maps: RawMaps::from(maps),
            policy: None,
            producer_id: producer.id,
        };
        let binding = load(
            &selection.binding()?,
            b"honk_hn_zone",
            NETFILTER,
            NETFILTER_ATTACH,
            &mut log,
        )?;
        let (producer_link, producer_link_id) = attach(producer.fd.as_fd(), config.family, -452)?;
        let (binding_link, binding_link_id) = attach(binding.fd.as_fd(), config.family, -199)?;
        let hooks = [
            HostNativeHook {
                family: config.family,
                hook: LOCAL_OUT,
                priority: -452,
                flags: 0,
                program_id: producer.id,
                link_id: producer_link_id,
            },
            HostNativeHook {
                family: config.family,
                hook: LOCAL_OUT,
                priority: -199,
                flags: 0,
                program_id: binding.id,
                link_id: binding_link_id,
            },
        ];
        Ok(Self {
            config: *config,
            root: maps.root.try_clone_to_owned()?,
            claims: maps.claims.try_clone_to_owned()?,
            scratch: maps.scratch.try_clone_to_owned()?,
            gate: maps.gate.try_clone_to_owned()?,
            sequence: maps.sequence.try_clone_to_owned()?,
            sockets: maps.sockets.try_clone_to_owned()?,
            socket_locks: maps.socket_locks.try_clone_to_owned()?,
            returns: maps.returns.try_clone_to_owned()?,
            dispatch,
            producer,
            binding,
            producer_link,
            binding_link,
            hooks,
            _layout_admission: admission,
        })
    }

    pub fn prepare(
        &self,
        policy: &NativeProgramConfig<'_>,
        actions: &[Option<u32>],
    ) -> io::Result<HostNativeCandidate> {
        require_closed(self.root.as_fd())?;
        if policy.root != self.root.as_raw_fd()
            && map_id_raw(policy.root)? != map_id(self.root.as_fd())?
        {
            return Err(invalid_data(
                "Host candidate belongs to another Native publication",
            ));
        }
        if map_id_raw(policy.claims)? != map_id(self.claims.as_fd())?
            || map_id_raw(policy.scratch)? != map_id(self.scratch.as_fd())?
            || policy.scope != self.config.scope
            || policy.epoch == 0
            || policy.epoch & 1 != 0
            || policy.epoch == u64::MAX - 1
            || policy.expires_boottime_ns == 0
            || policy.bytecode.is_empty()
        {
            return Err(invalid_data(
                "Host candidate has inconsistent publication identity",
            ));
        }
        let (selector_body, matcher_probe, scope_body, _) = self.program_bodies(policy, actions)?;
        let selection = Selection {
            owner: &self.config,
            maps: self.raw_maps(),
            policy: Some(policy),
            producer_id: self.producer.id,
        };
        let mut log = vec![0; PROGRAM_LIMIT];
        let mut first_matcher = Some(matcher_probe);
        let selector = load(
            &selector_body,
            b"honk_hn_select",
            NETFILTER,
            NETFILTER_ATTACH,
            &mut log,
        )?;
        drop(selector_body);
        let mut loaded = Vec::with_capacity(actions.len());
        let mut memory = selector.memory;
        for &mark in actions {
            let program = if let Some(program) = first_matcher.take() {
                program
            } else {
                selection.matcher(Some(mark))?
            };
            let matcher = load(&program, b"honk_hn_action", 1, 0, &mut log)?;
            memory = memory
                .checked_add(matcher.memory)
                .ok_or_else(|| invalid_data("Host program charge overflow"))?;
            if memory > PROGRAM_PARTITION / 4 {
                return Err(invalid_data(
                    "Host family generation exceeds its two-family/two-generation program partition",
                ));
            }
            loaded.push((mark, matcher));
        }
        let candidate_scope = load(&scope_body, b"honk_hn_scope", 1, 0, &mut log)?;
        memory = memory
            .checked_add(candidate_scope.memory)
            .ok_or_else(|| invalid_data("Host program charge overflow"))?;
        if memory > PROGRAM_PARTITION / 4 {
            return Err(invalid_data(
                "Host family generation exceeds its program partition",
            ));
        }
        Ok(HostNativeCandidate {
            selector,
            actions: loaded,
            candidate_scope,
            root_id: map_id(self.root.as_fd())?,
            dispatch_id: map_id(self.dispatch.as_fd())?,
            epoch: policy.epoch,
            scope: policy.scope,
            expires_boottime_ns: policy.expires_boottime_ns,
            memory,
        })
    }

    /// Uses the loader's exact bodies and bounds without requiring closed admission or loading BPF.
    pub fn program_memory_bytes(
        &self,
        policy: &NativeProgramConfig<'_>,
        actions: &[Option<u32>],
    ) -> io::Result<usize> {
        self.program_bodies(policy, actions)
            .map(|(_, _, _, bytes)| bytes)
    }

    fn program_bodies(
        &self,
        policy: &NativeProgramConfig<'_>,
        actions: &[Option<u32>],
    ) -> io::Result<(Program, Program, Program, usize)> {
        validate_actions(actions)?;
        Self::preparation_memory_bytes(policy.bytecode.len(), actions.len())?;
        let selection = Selection {
            owner: &self.config,
            maps: self.raw_maps(),
            policy: Some(policy),
            producer_id: self.producer.id,
        };
        let selector = selector_with(
            &self.config.source,
            selection.maps.source,
            0,
            Some(&selection),
        )?;
        // Keep and Set cases differ only in their two comparison immediates.
        let matcher = selection.matcher(Some(actions[0]))?;
        let scope = selection.matcher(None)?;
        let scope_upper = program_upper(scope.len)?;
        let generation = program_upper(selector.len)?
            .checked_add(
                program_upper(matcher.len)?
                    .checked_mul(actions.len())
                    .ok_or_else(|| invalid_data("Host matcher allocation overflow"))?,
            )
            .and_then(|v| v.checked_add(scope_upper))
            .ok_or_else(|| invalid_data("Host generation allocation overflow"))?;
        let stable = self.memory_bytes()?;
        let upper = generation
            .checked_mul(4)
            .and_then(|v| v.checked_add(stable.checked_mul(2)?))
            .ok_or_else(|| invalid_data("Host active/candidate program allocation overflow"))?;
        if upper > PROGRAM_PARTITION {
            return Err(invalid_data(
                "Host action/bytecode bound exceeds the 16MiB program partition",
            ));
        }
        Ok((selector, matcher, scope, generation))
    }

    /// Includes simultaneous bytecode construction and the verifier log; reserve before loading.
    pub fn preparation_memory_bytes(bytecode: usize, actions: usize) -> io::Result<usize> {
        if bytecode == 0 || actions == 0 || actions > MAX_ACTIONS {
            return Err(invalid_data("invalid Host program/action count"));
        }
        let insns = bytecode
            .checked_add(WRAPPER_INSNS)
            .filter(|n| *n <= MAX_PROGRAM_INSNS)
            .ok_or_else(|| invalid_data("Host bytecode exceeds instruction ceiling"))?;
        let raw = insns
            .checked_mul(8)
            .ok_or_else(|| invalid_data("Host instruction allocation overflow"))?;
        raw.checked_mul(4)
            .and_then(|v| v.checked_add(PROGRAM_LIMIT + 65536))
            .ok_or_else(|| invalid_data("Host loader staging overflow"))
    }

    pub fn publish_selector(&self, candidate: &HostNativeCandidate) -> io::Result<()> {
        let closed = require_closed(self.root.as_fd())?;
        if candidate.root_id != map_id(self.root.as_fd())?
            || candidate.dispatch_id != map_id(self.dispatch.as_fd())?
            || candidate.epoch != closed
            || candidate.scope != self.config.scope
        {
            return Err(invalid_data(
                "Host selector publication identity/closed epoch mismatch",
            ));
        }
        let key = 0u32;
        let value = candidate.selector.fd.as_raw_fd() as u32;
        let mut attr = map_attr(self.dispatch.as_fd(), &key, &value as *const _ as u64);
        bpf(BPF_MAP_UPDATE_ELEM, &mut attr)?;
        let actual: u32 = map_value(self.dispatch.as_fd(), &key)?;
        if actual != candidate.selector.id {
            return Err(invalid_data("Host selector dispatch ID readback mismatch"));
        }
        Ok(())
    }
    pub fn close_admission(&self) -> io::Result<()> {
        require_closed(self.root.as_fd())?;
        let mut attr = map_attr(self.dispatch.as_fd(), &0u32, 0);
        match bpf(BPF_MAP_DELETE_ELEM, &mut attr) {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(e) => Err(e),
        }
    }
    pub fn hooks(&self) -> &[HostNativeHook; 2] {
        &self.hooks
    }
    pub fn map_ids(&self) -> io::Result<[(&'static str, u32); 9]> {
        let mut result = [("", 0); 9];
        for (slot, (name, fd)) in result.iter_mut().zip([
            ("root", self.root.as_fd()),
            ("claims", self.claims.as_fd()),
            ("scratch", self.scratch.as_fd()),
            ("gate", self.gate.as_fd()),
            ("sequence", self.sequence.as_fd()),
            ("sockets", self.sockets.as_fd()),
            ("socket_locks", self.socket_locks.as_fd()),
            ("returns", self.returns.as_fd()),
            ("dispatch", self.dispatch.as_fd()),
        ]) {
            *slot = (name, map_id(fd)?);
        }
        Ok(result)
    }
    pub const fn stable_preparation_memory_bytes() -> usize {
        PROGRAM_LIMIT + 2 * WRAPPER_INSNS * 8 + 65536
    }
    /// Call after the parent's closed-root reader grace and exact custody check.
    pub fn detach_links(&self) -> io::Result<()> {
        require_closed(self.root.as_fd())?;
        let binding = bpf(34, &mut (self.binding_link.as_raw_fd() as u32));
        let producer = bpf(34, &mut (self.producer_link.as_raw_fd() as u32));
        match (binding, producer) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(first), Err(second)) => Err(io::Error::other(format!(
                "Host binding detach: {first}; producer detach: {second}"
            ))),
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        }
    }
    pub fn producer(&self) -> (BorrowedFd<'_>, u32) {
        (self.producer.fd.as_fd(), self.producer.id)
    }
    pub fn binding_program(&self) -> (BorrowedFd<'_>, u32) {
        (self.binding.fd.as_fd(), self.binding.id)
    }
    pub fn check_links(&self) -> io::Result<()> {
        for (fd, expected) in [
            (self.producer_link.as_fd(), self.hooks[0]),
            (self.binding_link.as_fd(), self.hooks[1]),
        ] {
            check_link(fd, expected)?;
        }
        Ok(())
    }
    pub fn memory_bytes(&self) -> io::Result<usize> {
        let maps = usize::try_from(fd_memlock(self.dispatch.as_fd())?).map_err(io::Error::other)?;
        maps.checked_add(self.producer.memory)
            .and_then(|v| v.checked_add(self.binding.memory))
            .and_then(|v| v.checked_add(8192))
            .ok_or_else(|| invalid_data("Host stable-program charge overflow"))
    }
    fn raw_maps(&self) -> RawMaps {
        RawMaps {
            root: self.root.as_raw_fd(),
            claims: self.claims.as_raw_fd(),
            scratch: self.scratch.as_raw_fd(),
            source: Maps {
                facts: -1,
                gate: self.gate.as_raw_fd(),
                sequence: self.sequence.as_raw_fd(),
                sockets: self.sockets.as_raw_fd(),
                socket_locks: self.socket_locks.as_raw_fd(),
                returns: self.returns.as_raw_fd(),
            },
        }
    }
}

#[derive(Clone, Copy)]
struct RawMaps {
    root: RawFd,
    claims: RawFd,
    scratch: RawFd,
    source: Maps,
}
impl From<HostNativeMaps<'_>> for RawMaps {
    fn from(m: HostNativeMaps<'_>) -> Self {
        Self {
            root: m.root.as_raw_fd(),
            claims: m.claims.as_raw_fd(),
            scratch: m.scratch.as_raw_fd(),
            source: Maps {
                facts: -1,
                gate: m.gate.as_raw_fd(),
                sequence: m.sequence.as_raw_fd(),
                sockets: m.sockets.as_raw_fd(),
                socket_locks: m.socket_locks.as_raw_fd(),
                returns: m.returns.as_raw_fd(),
            },
        }
    }
}

pub(super) struct Selection<'a> {
    owner: &'a HostNativeConfig,
    maps: RawMaps,
    policy: Option<&'a NativeProgramConfig<'a>>,
    producer_id: u32,
}

fn copy(b: &mut Builder, dest: u8, to: i16, source: u8, from: i16, bytes: i16) {
    for offset in (0..bytes).step_by(4) {
        b.emit(Insn::new(LDX_W, 0, source, from + offset, 0));
        b.emit(Insn::new(STX_W, dest, 0, to + offset, 0));
    }
}
fn zero(b: &mut Builder, reg: u8, offset: i16, bytes: i16) {
    for off in (offset..offset + bytes).step_by(4) {
        b.emit(Insn::new(ST_W, reg, 0, off, 0));
    }
}
fn same64(b: &mut Builder, left: u8, lo: i16, right: u8, ro: i16, failure: Label) {
    b.emit(Insn::new(LDX_DW, 0, left, lo, 0));
    b.emit(Insn::new(LDX_DW, 1, right, ro, 0));
    b.jump(Insn::new(JNE_X, 0, 1, 0, 0), failure);
}

impl Selection<'_> {
    fn layout(&self) -> &HostNativeLayout {
        &self.owner.layout
    }
    fn source(&self) -> &HostSourceConfig {
        &self.owner.source
    }
    fn policy(&self) -> &NativeProgramConfig<'_> {
        self.policy
            .expect("policy emission requires an admitted candidate")
    }
    pub(super) fn reserve(&self, b: &mut Builder) -> io::Result<()> {
        let length = WRAPPER_INSNS
            .checked_add(self.policy().bytecode.len())
            .ok_or_else(|| invalid_data("Host source instruction reservation overflow"))?;
        b.reserve(length)
    }
    pub(super) fn restore_bank(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_DW, 6, 10, SAVED_BANK, 0));
        b.emit(Insn::new(LDX_DW, 7, 10, M + 48, 0));
        b.emit(Insn::new(LDX_DW, 8, 10, E + 8, 0));
        // Empty optional process entries still refer to the current actual socket.
        b.emit(Insn::new(LDX_DW, 0, 10, KSKB, 0));
        read_kernel(b, 0, self.source().skb_sk_offset, 8, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_DW, 8, 10, SCRATCH, 0));
    }
    pub(super) fn origin(&self, b: &mut Builder) {
        b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
        zero(b, 10, M, 128);
        b.emit(Insn::new(0x7a, 10, 0, NSCRATCH, 0));
        b.emit(Insn::new(0x7a, 10, 0, TOKEN, 0));
        b.emit(Insn::new(LDX_DW, 0, 9, 8, 0));
        b.emit(Insn::new(STX_DW, 10, 0, KSKB, 0));
        b.emit(Insn::new(LDX_DW, 6, 9, 0, 0));
        read_kernel(b, 6, self.layout().state_hook, 1, SCRATCH, Label::Drop);
        require(b, LDX_B, 10, SCRATCH, LOCAL_OUT as i32);
        read_kernel(b, 6, self.layout().state_pf, 1, SCRATCH, Label::Drop);
        require(b, LDX_B, 10, SCRATCH, self.owner.family as i32);
        read_kernel(b, 6, self.layout().state_net, 8, NET, Label::Drop);
        read_kernel(b, 6, self.layout().state_out, 8, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_DW, 6, 10, SCRATCH, 0));
        b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Drop);
        read_kernel(b, 6, self.layout().dev_ifindex, 4, M + 64, Label::Drop);
        self.socket_origin(b, false);
    }
    fn socket_origin(&self, b: &mut Builder, matcher: bool) {
        b.emit(Insn::new(LDX_DW, 0, 10, KSKB, 0));
        read_kernel(b, 0, self.source().skb_sk_offset, 8, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_DW, 8, 10, SCRATCH, 0));
        b.jump(Insn::new(JEQ_K, 8, 0, 0, 0), Label::Pass);
        read_kernel(b, 8, self.layout().sock_family, 2, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_H, 0, 10, SCRATCH, 0));
        let inet = ahead(b, JEQ_K, 0, 0, libc::AF_INET);
        b.jump(Insn::new(JNE_K, 0, 0, 0, libc::AF_INET6), Label::Pass);
        patch(b, inet);
        b.emit(Insn::new(STX_H, 10, 0, M + 102, 0));
        read_kernel(b, 8, self.layout().sock_state, 1, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_B, 0, 10, SCRATCH, 0));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 6), Label::Pass);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 12), Label::Pass);
        read_kernel(
            b,
            8,
            self.source().sock_net_pointer_offset,
            8,
            SCRATCH,
            Label::Drop,
        );
        b.emit(Insn::new(LDX_DW, 6, 10, SCRATCH, 0));
        b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Drop);
        if matcher {
            b.emit(Insn::new(STX_DW, 10, 6, NET, 0));
        } else {
            same64(b, 10, NET, 10, SCRATCH, Label::Drop);
        }
        read_kernel(
            b,
            6,
            self.source().net_cookie_offset,
            8,
            M + 32,
            Label::Drop,
        );
        b.emit(Insn::new(LDX_DW, 0, 10, M + 32, 0));
        imm(b, 1, self.source().source_netns);
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Pass);
        read_kernel(b, 8, self.layout().sock_type, 2, M + 76, Label::Drop);
        b.emit(Insn::new(LDX_H, 0, 10, M + 76, 0));
        let udp = ahead(b, JEQ_K, 0, 0, 2);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 1), Label::Pass);
        patch(b, udp);
        read_kernel(b, 8, self.layout().sock_protocol, 2, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_H, 0, 10, SCRATCH, 0));
        b.emit(Insn::new(STX_W, 10, 0, PROTOCOL, 0));
        let udp = ahead(b, JEQ_K, 0, 0, 17);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 6), Label::Pass);
        b.emit(Insn::new(LDX_H, 0, 10, M + 76, 0));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 1), Label::Pass);
        let typed = ahead(b, JA, 0, 0, 0);
        patch(b, udp);
        b.emit(Insn::new(LDX_H, 0, 10, M + 76, 0));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 2), Label::Pass);
        patch(b, typed);
        read_kernel(b, 8, self.layout().sock_cookie, 8, M + 48, Label::Drop);
        b.emit(Insn::new(LDX_DW, 7, 10, M + 48, 0));
        b.jump(Insn::new(JEQ_K, 7, 0, 0, 0), Label::Pass);
        read_kernel(b, 8, self.layout().sock_mark, 4, M + 72, Label::Drop);
        b.emit(Insn::new(LDX_DW, 6, 10, KSKB, 0));
        read_kernel(b, 6, self.layout().skb_mark, 4, M + 68, Label::Drop);
        read_kernel(b, 6, self.layout().skb_len, 4, LENGTH, Label::Drop);
        read_kernel(b, 6, self.layout().skb_data_len, 4, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_W, 0, 10, LENGTH, 0));
        b.emit(Insn::new(LDX_W, 1, 10, SCRATCH, 0));
        b.jump(Insn::new(JGT_X, 1, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(0x1f, 0, 1, 0, 0));
        b.emit(Insn::new(STX_W, 10, 0, LINEAR, 0));
        read_kernel(b, 6, self.layout().skb_data, 8, DATA, Label::Drop);
        read_kernel(b, 6, self.layout().skb_protocol, 2, ETHER, Label::Drop);
        if matcher {
            read_kernel(b, 6, self.layout().skb_refdst, 8, SCRATCH, Label::Drop);
            b.emit(Insn::new(LDX_DW, 6, 10, SCRATCH, 0));
            b.emit(Insn::new(AND_K, 6, 0, 0, -4));
            b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Drop);
            read_kernel(b, 6, self.layout().dst_dev, 8, SCRATCH, Label::Drop);
            b.emit(Insn::new(LDX_DW, 6, 10, SCRATCH, 0));
            b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Drop);
            read_kernel(b, 6, self.layout().dev_net, 8, SCRATCH, Label::Drop);
            same64(b, 10, SCRATCH, 10, NET, Label::Drop);
            read_kernel(b, 6, self.layout().dev_ifindex, 4, M + 64, Label::Drop);
        }
    }
    pub(super) fn packet_word(&self, b: &mut Builder, reg: u8, offset: i16) {
        b.emit(Insn::new(
            if offset == 16 { LDX_H } else { LDX_W },
            reg,
            10,
            if offset == 16 { ETHER } else { LENGTH },
            0,
        ));
    }
    pub(super) fn packet_load(&self, b: &mut Builder, offset: Option<i32>, dest: i16, size: i32) {
        if let Some(offset) = offset {
            b.emit(Insn::new(MOV_K, 2, 0, 0, offset));
        }
        b.emit(Insn::new(MOV_X, 0, 2, 0, 0));
        b.jump(Insn::new(JGT_K, 0, 0, 0, 65535), Label::Drop);
        b.emit(Insn::new(ADD_K, 0, 0, 0, size));
        b.emit(Insn::new(LDX_W, 1, 10, LINEAR, 0));
        b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_DW, 3, 10, DATA, 0));
        b.emit(Insn::new(ADD_X, 3, 2, 0, 0));
        stack(b, 1, dest);
        b.emit(Insn::new(MOV_K, 2, 0, 0, size));
        b.emit(Insn::new(CALL, 0, 0, 0, 113));
    }
}

impl Selection<'_> {
    fn packet_key(&self, b: &mut Builder) {
        const HEADER: i16 = -384;
        const OFFSET: i16 = -388;
        const END: i16 = -392;
        const NEXT: i16 = -396;
        zero(b, 10, NKEY, 56);
        self.packet_load(b, Some(0), HEADER, 20);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        self.packet_word(b, 0, 16);
        let v6 = ahead(b, JNE_K, 0, 0, 0x0800u16.to_be() as i32);
        b.emit(Insn::new(LDX_B, 0, 10, HEADER, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0x40), Label::Drop);
        b.emit(Insn::new(LDX_H, 0, 10, HEADER + 6, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, 0x3fffu16.to_be() as i32));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        for off in [8, 24] {
            b.emit(Insn::new(
                ST_W,
                10,
                0,
                NKEY + off,
                u32::from_ne_bytes([0, 0, 255, 255]) as i32,
            ));
        }
        copy(b, 10, NKEY + 12, 10, HEADER + 12, 4);
        copy(b, 10, NKEY + 28, 10, HEADER + 16, 4);
        b.emit(Insn::new(LDX_B, 0, 10, HEADER + 1, 0));
        b.emit(Insn::new(RSH_K, 0, 0, 0, 2));
        b.emit(Insn::new(STX_W, 10, 0, M + 12, 0));
        b.emit(Insn::new(0x72, 10, 0, NKEY + 37, 4));
        b.emit(Insn::new(LDX_B, 0, 10, HEADER + 9, 0));
        b.emit(Insn::new(0x73, 10, 0, NKEY + 36, 0));
        b.emit(Insn::new(LDX_H, 0, 10, HEADER + 2, 0));
        b.emit(Insn::new(BE16, 0, 0, 0, 16));
        b.emit(Insn::new(STX_W, 10, 0, END, 0));
        b.emit(Insn::new(LDX_B, 0, 10, HEADER, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, 15));
        b.jump(Insn::new(JLT_K, 0, 0, 0, 5), Label::Drop);
        b.emit(Insn::new(LSH_K, 0, 0, 0, 2));
        b.emit(Insn::new(STX_W, 10, 0, OFFSET, 0));
        let ports = ahead(b, JA, 0, 0, 0);
        patch(b, v6);
        self.packet_word(b, 0, 16);
        b.jump(
            Insn::new(JNE_K, 0, 0, 0, 0x86ddu16.to_be() as i32),
            Label::Drop,
        );
        require(b, LDX_H, 10, M + 102, libc::AF_INET6);
        self.packet_load(b, Some(0), HEADER, 40);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_B, 0, 10, HEADER, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, 0xf0));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0x60), Label::Drop);
        copy(b, 10, NKEY, 10, HEADER + 8, 32);
        b.emit(Insn::new(LDX_H, 0, 10, HEADER, 0));
        b.emit(Insn::new(BE16, 0, 0, 0, 16));
        b.emit(Insn::new(RSH_K, 0, 0, 0, 6));
        b.emit(Insn::new(AND_K, 0, 0, 0, 63));
        b.emit(Insn::new(STX_W, 10, 0, M + 12, 0));
        b.emit(Insn::new(0x72, 10, 0, NKEY + 37, 6));
        b.emit(Insn::new(LDX_H, 0, 10, HEADER + 4, 0));
        b.emit(Insn::new(BE16, 0, 0, 0, 16));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(ADD_K, 0, 0, 0, 40));
        b.emit(Insn::new(STX_W, 10, 0, END, 0));
        b.emit(Insn::new(ST_W, 10, 0, OFFSET, 40));
        b.emit(Insn::new(LDX_B, 0, 10, HEADER + 6, 0));
        b.emit(Insn::new(STX_W, 10, 0, NEXT, 0));
        let mut found = Vec::with_capacity(18);
        for _ in 0..8 {
            b.emit(Insn::new(LDX_W, 0, 10, NEXT, 0));
            found.push(ahead(b, JEQ_K, 0, 0, 6));
            found.push(ahead(b, JEQ_K, 0, 0, 17));
            let hop = ahead(b, JEQ_K, 0, 0, 0);
            let routing = ahead(b, JEQ_K, 0, 0, 43);
            let destination = ahead(b, JEQ_K, 0, 0, 60);
            b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
            patch(b, hop);
            patch(b, routing);
            patch(b, destination);
            b.emit(Insn::new(LDX_W, 2, 10, OFFSET, 0));
            self.packet_load(b, None, HEADER, 4);
            b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
            b.emit(Insn::new(LDX_W, 0, 10, NEXT, 0));
            let not_routing = ahead(b, JNE_K, 0, 0, 43);
            require(b, LDX_B, 10, HEADER + 3, 0);
            patch(b, not_routing);
            b.emit(Insn::new(LDX_B, 0, 10, HEADER + 1, 0));
            b.emit(Insn::new(ADD_K, 0, 0, 0, 1));
            b.emit(Insn::new(LSH_K, 0, 0, 0, 3));
            b.emit(Insn::new(LDX_W, 1, 10, OFFSET, 0));
            b.emit(Insn::new(ADD_X, 0, 1, 0, 0));
            b.emit(Insn::new(LDX_W, 1, 10, END, 0));
            b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
            b.emit(Insn::new(STX_W, 10, 0, OFFSET, 0));
            b.emit(Insn::new(LDX_B, 0, 10, HEADER, 0));
            b.emit(Insn::new(STX_W, 10, 0, NEXT, 0));
        }
        b.emit(Insn::new(LDX_W, 0, 10, NEXT, 0));
        found.push(ahead(b, JEQ_K, 0, 0, 6));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 17), Label::Drop);
        for at in found {
            patch(b, at);
        }
        b.emit(Insn::new(LDX_W, 0, 10, NEXT, 0));
        b.emit(Insn::new(0x73, 10, 0, NKEY + 36, 0));
        patch(b, ports);
        b.emit(Insn::new(LDX_B, 0, 10, NKEY + 36, 0));
        b.emit(Insn::new(LDX_W, 1, 10, PROTOCOL, 0));
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_W, 0, 10, END, 0));
        b.emit(Insn::new(LDX_W, 1, 10, LENGTH, 0));
        b.jump(Insn::new(JGT_X, 0, 1, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_W, 2, 10, OFFSET, 0));
        b.emit(Insn::new(MOV_X, 1, 2, 0, 0));
        b.emit(Insn::new(ADD_K, 1, 0, 0, 8));
        b.jump(Insn::new(JGT_X, 1, 0, 0, 0), Label::Drop);
        self.packet_load(b, None, HEADER, 8);
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        copy(b, 10, NKEY + 32, 10, HEADER, 4);
        b.emit(Insn::new(
            0x72,
            10,
            0,
            NKEY + 38,
            NATIVE_DOMAIN_SOURCE as i32,
        ));
        imm(b, 0, self.source().source_netns);
        b.emit(Insn::new(STX_DW, 10, 0, NKEY + 40, 0));
    }

    fn acquire_scratch(&self, b: &mut Builder) {
        b.emit(Insn::new(CALL, 0, 0, 0, 8));
        b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
        lookup(b, self.maps.scratch, KEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
        b.emit(Insn::new(MOV_K, 1, 0, 0, 1));
        b.emit(Insn::new(0xc3, 6, 1, S_BUSY, 0xf1));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(STX_DW, 10, 6, NSCRATCH, 0));
    }
    fn root(&self, b: &mut Builder) {
        b.emit(Insn::new(ST_W, 10, 0, KEY, 0));
        lookup(b, self.maps.root, KEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(STX_DW, 10, 0, ROOT_POINTER, 0));
        b.emit(Insn::new(LDX_DW, 1, 0, 0, 0));
        // The owner's post-swap RCU Grace ends old nft/selector invocations before reopen.
        b.emit(Insn::new(MOV_X, 2, 1, 0, 0));
        b.emit(Insn::new(AND_K, 2, 0, 0, 1));
        b.jump(Insn::new(JEQ_K, 2, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(STX_DW, 10, 1, OPEN_EPOCH, 0));
        require(b, LDX_W, 0, 12, 0);
    }

    fn source_identity(&self, b: &mut Builder, reg: u8, failure: Label) {
        same64(b, reg, 40, 10, M + 48, failure);
        same64(b, reg, 48, 10, M + 104, failure);
        b.emit(Insn::new(LDX_DW, 0, reg, 48, 0));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), failure);
        b.emit(Insn::new(LDX_DW, 0, reg, 56, 0));
        imm(b, 1, self.source().attachment);
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), failure);
        b.emit(Insn::new(LDX_DW, 0, reg, 16, 0));
        imm(b, 1, self.owner.scope);
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), failure);
        b.emit(Insn::new(LDX_DW, 0, reg, 0, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, 1));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), failure);
        same64(b, reg, 8, reg, 0, failure);
        b.emit(Insn::new(LDX_W, 0, reg, 64, 0));
        b.jump(Insn::new(JGT_K, 0, 0, 0, ROUTING_MARK_SET as i32), failure);
        let set = ahead(b, JEQ_K, 0, 0, ROUTING_MARK_SET as i32);
        b.emit(Insn::new(LDX_W, 0, reg, 68, 0));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), failure);
        patch(b, set);
    }

    fn canonical(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_DW, 6, 10, NSCRATCH, 0));
        zero(
            b,
            6,
            S_INPUT,
            (size_of::<RoutingInput>() + size_of::<KernelRouteOutput>()) as i16,
        );
        copy(b, 6, S_INPUT, 10, NKEY, 32);
        for (from, name) in [
            (32, std::mem::offset_of!(RoutingInput, src_port)),
            (34, std::mem::offset_of!(RoutingInput, dst_port)),
        ] {
            b.emit(Insn::new(LDX_H, 0, 10, NKEY + from, 0));
            b.emit(Insn::new(BE16, 0, 0, 0, 16));
            b.emit(Insn::new(STX_W, 6, 0, S_INPUT + name as i16, 0));
        }
        for (from, wire, first, second, name) in [
            (
                36,
                6,
                L4ProtoType::Tcp as i32,
                L4ProtoType::Udp as i32,
                std::mem::offset_of!(RoutingInput, l4proto),
            ),
            (
                37,
                4,
                IpVersionType::V4 as i32,
                IpVersionType::V6 as i32,
                std::mem::offset_of!(RoutingInput, ip_version),
            ),
        ] {
            b.emit(Insn::new(LDX_B, 0, 10, NKEY + from, 0));
            b.emit(Insn::new(MOV_K, 1, 0, 0, first));
            let first = ahead(b, JEQ_K, 0, 0, wire);
            b.emit(Insn::new(MOV_K, 1, 0, 0, second));
            patch(b, first);
            b.emit(Insn::new(STX_W, 6, 1, S_INPUT + name as i16, 0));
        }
        b.emit(Insn::new(
            ST_W,
            6,
            0,
            S_INPUT + std::mem::offset_of!(RoutingInput, is_wan) as i16,
            1,
        ));
        b.emit(Insn::new(LDX_DW, 0, 10, ROOT_POINTER, 0));
        b.emit(Insn::new(LDX_W, 0, 0, 8, 0));
        b.emit(Insn::new(
            AND_K,
            0,
            0,
            0,
            DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as i32,
        ));
        let no_finality = ahead(b, JEQ_K, 0, 0, 0);
        b.emit(Insn::new(
            ST_W,
            6,
            0,
            S_INPUT + std::mem::offset_of!(RoutingInput, flags) as i16,
            ROUTING_INPUT_ALLOW_DIRECT_FINALITY as i32,
        ));
        patch(b, no_finality);
        b.emit(Insn::new(LDX_W, 0, 10, M + 12, 0));
        b.emit(Insn::new(
            STX_W,
            6,
            0,
            S_INPUT + std::mem::offset_of!(RoutingInput, dscp) as i16,
            0,
        ));
        b.emit(Insn::new(LDX_W, 0, 10, E + 36, 0));
        b.emit(Insn::new(
            AND_K,
            0,
            0,
            0,
            HOST_SOCKET_PROCESS_PRESENT as i32,
        ));
        let missing = ahead(b, JEQ_K, 0, 0, 0);
        copy(
            b,
            6,
            S_INPUT + std::mem::offset_of!(RoutingInput, pname) as i16,
            10,
            E + 20,
            16,
        );
        b.emit(Insn::new(MOV_K, 2, 0, 0, 0));
        let mut ends = Vec::with_capacity(16);
        for byte in 0..16 {
            b.emit(Insn::new(LDX_B, 0, 10, E + 20 + byte, 0));
            ends.push(ahead(b, JEQ_K, 0, 0, 0));
            b.emit(Insn::new(MOV_K, 2, 0, 0, byte as i32 + 1));
        }
        for at in ends {
            patch(b, at);
        }
        b.emit(Insn::new(
            STX_W,
            6,
            2,
            S_INPUT + std::mem::offset_of!(RoutingInput, pname_len) as i16,
            0,
        ));
        patch(b, missing);
        b.emit(Insn::new(MOV_X, 1, 6, 0, 0));
        b.emit(Insn::new(ADD_K, 1, 0, 0, S_INPUT as i32));
        b.emit(Insn::new(MOV_X, 2, 6, 0, 0));
        b.emit(Insn::new(ADD_K, 2, 0, 0, S_OUTPUT as i32));
        b.emit(Insn::new(CALL, 0, 1, 0, CANONICAL_CALL));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_DW, 6, 10, NSCRATCH, 0));
        for (from, to) in [
            (
                std::mem::offset_of!(KernelRouteOutput, mark_kind),
                MARK_KIND,
            ),
            (std::mem::offset_of!(RoutingDecision, mark), MARK_VALUE),
        ] {
            b.emit(Insn::new(LDX_W, 0, 6, S_OUTPUT + from as i16, 0));
            b.emit(Insn::new(STX_W, 10, 0, to, 0));
        }
        b.emit(Insn::new(LDX_W, 0, 10, MARK_KIND, 0));
        b.jump(
            Insn::new(JGT_K, 0, 0, 0, ROUTING_MARK_SET as i32),
            Label::Drop,
        );
        let set = ahead(b, JEQ_K, 0, 0, ROUTING_MARK_SET as i32);
        require(b, LDX_W, 10, MARK_VALUE, 0);
        patch(b, set);
    }

    fn decide(&self, b: &mut Builder) {
        b.emit(Insn::new(ST_W, 10, 0, CHOICE, HOST_SOCKET_ENDPOINT as i32));
        b.emit(Insn::new(
            LDX_W,
            0,
            6,
            S_OUTPUT + std::mem::offset_of!(RoutingDecision, outbound) as i16,
            0,
        ));
        let block = ahead(b, JEQ_K, 0, 0, 1);
        b.emit(Insn::new(
            LDX_W,
            0,
            6,
            S_OUTPUT + std::mem::offset_of!(RoutingDecision, must) as i16,
            0,
        ));
        let must_routed = ahead(b, JNE_K, 0, 0, 0);
        b.emit(Insn::new(LDX_H, 0, 10, NKEY + 34, 0));
        let dns = ahead(b, JEQ_K, 0, 0, 53u16.to_be() as i32);
        b.emit(Insn::new(LDX_DW, 0, 10, ROOT_POINTER, 0));
        b.emit(Insn::new(LDX_W, 0, 0, 8, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, DATAPATH_FLAG_OFFLOAD_ALL as i32));
        let normal = ahead(b, JEQ_K, 0, 0, 0);
        b.emit(Insn::new(
            LDX_W,
            0,
            6,
            S_OUTPUT + std::mem::offset_of!(RoutingDecision, outbound) as i16,
            0,
        ));
        let direct = ahead(b, JEQ_K, 0, 0, 0);
        b.emit(Insn::new(ST_W, 10, 0, MARK_KIND, ROUTING_MARK_KEEP as i32));
        b.emit(Insn::new(ST_W, 10, 0, MARK_VALUE, 0));
        patch(b, direct);
        b.emit(Insn::new(ST_W, 10, 0, CHOICE, HOST_SOCKET_NATIVE as i32));
        let mode_selected = ahead(b, JA, 0, 0, 0);
        patch(b, must_routed);
        patch(b, normal);
        b.emit(Insn::new(
            LDX_W,
            0,
            6,
            S_OUTPUT + std::mem::offset_of!(RoutingDecision, outbound) as i16,
            0,
        ));
        let non_direct = ahead(b, JNE_K, 0, 0, 0);
        b.emit(Insn::new(
            LDX_W,
            0,
            6,
            S_OUTPUT + std::mem::offset_of!(RoutingDecision, must) as i16,
            0,
        ));
        let must = ahead(b, JNE_K, 0, 0, 0);
        b.emit(Insn::new(LDX_H, 0, 10, NKEY + 34, 0));
        let dns_normal = ahead(b, JEQ_K, 0, 0, 53u16.to_be() as i32);
        b.emit(Insn::new(LDX_DW, 0, 10, ROOT_POINTER, 0));
        b.emit(Insn::new(LDX_W, 0, 0, 8, 0));
        b.emit(Insn::new(
            AND_K,
            0,
            0,
            0,
            DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as i32,
        ));
        let disabled = ahead(b, JEQ_K, 0, 0, 0);
        b.emit(Insn::new(
            LDX_W,
            0,
            6,
            S_OUTPUT + std::mem::offset_of!(RoutingDecision, domain_final) as i16,
            0,
        ));
        let not_final = ahead(b, JEQ_K, 0, 0, 0);
        patch(b, must);
        b.emit(Insn::new(ST_W, 10, 0, CHOICE, HOST_SOCKET_NATIVE as i32));
        for at in [
            block,
            dns,
            mode_selected,
            non_direct,
            dns_normal,
            disabled,
            not_final,
        ] {
            patch(b, at);
        }
    }

    pub(super) fn prepare(&self, b: &mut Builder) {
        require(b, LDX_W, 10, E + 60, 0);
        b.emit(Insn::new(LDX_W, 0, 10, E + 36, 0));
        b.emit(Insn::new(
            AND_K,
            0,
            0,
            0,
            !(HOST_SOCKET_PROCESS_PRESENT as i32),
        ));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        b.jump(
            Insn::new(JGT_K, 0, 0, 0, HOST_SOCKET_NATIVE as i32),
            Label::Drop,
        );
        b.emit(Insn::new(STX_DW, 10, 6, SAVED_BANK, 0));
        b.emit(Insn::new(LDX_DW, 0, 10, E + 40, 0));
        b.emit(Insn::new(STX_DW, 10, 0, M + 104, 0));
        b.emit(Insn::new(ST_W, 10, 0, RETAINED, 0));
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        let frozen_endpoint = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
        let frozen_native = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_NATIVE as i32);
        b.emit(Insn::new(LDX_W, 1, 10, M + 72, 0));
        b.jump(
            Insn::new(JEQ32_K, 1, 0, 0, self.source().bypass_mark as i32),
            Label::Pass,
        );
        patch(b, frozen_endpoint);
        patch(b, frozen_native);
        b.emit(Insn::new(LDX_W, 0, 10, PROTOCOL, 0));
        let udp = ahead(b, JEQ_K, 0, 0, 17);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        let candidate = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_CANDIDATE as i32);
        let endpoint = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
        let native = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_NATIVE as i32);
        let ineligible_tcp = ahead(b, JA, 0, 0, 0);
        for at in [udp, candidate, endpoint, native] {
            patch(b, at);
        }
        b.emit(Insn::new(LDX_W, 0, 10, DEVICE, 0));
        let selected = ahead(b, JNE_K, 0, 0, 0);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        let frozen_native = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_NATIVE as i32);
        let frozen_endpoint = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
        let ordinary = ahead(b, JA, 0, 0, 0);
        patch(b, selected);
        patch(b, frozen_native);
        patch(b, frozen_endpoint);
        require(b, LDX_W, 10, READY, 1);
        self.root(b);
        self.packet_key(b);
        self.acquire_scratch(b);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        let endpoint = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
        lookup(b, self.maps.claims, NKEY);
        let absent = ahead(b, JEQ_K, 0, 0, 0);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(b, 6, Label::Drop);
        require(b, LDX_W, 6, 24, NATIVE_EXECUTOR_KERNEL as i32);
        self.native_phase(b, 6);
        let armed = ahead(b, JEQ_K, 0, 0, NATIVE_PHASE_ARMED as i32);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        b.jump(
            Insn::new(JNE_K, 0, 0, 0, HOST_SOCKET_NATIVE as i32),
            Label::Drop,
        );
        b.emit(Insn::new(LDX_W, 0, 10, PROTOCOL, 0));
        let tcp = ahead(b, JNE_K, 0, 0, 17);
        for offset in [32, 34] {
            b.emit(Insn::new(LDX_H, 0, 10, NKEY + offset, 0));
            b.jump(Insn::new(JEQ_K, 0, 0, 0, 53u16.to_be() as i32), Label::Ipv6);
        }
        patch(b, tcp);
        self.retained_effect(b, 6);
        b.emit(Insn::new(ST_W, 10, 0, CHOICE, HOST_SOCKET_NATIVE as i32));
        let frozen = ahead(b, JA, 0, 0, 0);
        patch(b, armed);
        patch(b, absent);
        b.label(Label::Ipv6);
        self.canonical(b);
        self.decide(b);
        patch(b, frozen);
        let classified = ahead(b, JA, 0, 0, 0);
        patch(b, endpoint);
        b.emit(Insn::new(ST_W, 10, 0, CHOICE, HOST_SOCKET_ENDPOINT as i32));
        patch(b, classified);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        let frozen_endpoint = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
        let new_selection = ahead(b, JNE_K, 0, 0, HOST_SOCKET_NATIVE as i32);
        require(b, LDX_W, 10, CHOICE, HOST_SOCKET_NATIVE as i32);
        patch(b, frozen_endpoint);
        self.pending(b);
        patch(b, new_selection);
        patch(b, ordinary);
        patch(b, ineligible_tcp);
        self.restore_bank(b);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
    }

    fn retained_effect(&self, b: &mut Builder, reg: u8) {
        b.emit(Insn::new(LDX_W, 0, 10, PROTOCOL, 0));
        let tcp = ahead(b, JNE_K, 0, 0, 17);
        b.emit(Insn::new(CALL, 0, 0, 0, 5));
        b.emit(Insn::new(MOV_X, 2, 0, 0, 0));
        b.emit(Insn::new(LDX_DW, 0, reg, 32, 0));
        let current = ahead(b, JGE_X, 0, 2, 0);
        self.udp_idle_deadline(b);
        patch(b, current);
        patch(b, tcp);
        for (from, to) in [(64, MARK_KIND), (68, MARK_VALUE)] {
            b.emit(Insn::new(LDX_W, 0, reg, from, 0));
            b.emit(Insn::new(STX_W, 10, 0, to, 0));
        }
        b.emit(Insn::new(ST_W, 10, 0, RETAINED, 1));
    }

    fn udp_idle_deadline(&self, b: &mut Builder) {
        b.emit(Insn::new(MOV_X, 3, 2, 0, 0));
        b.emit(Insn::new(0x1f, 3, 0, 0, 0));
        imm(b, 4, honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS);
        b.jump(Insn::new(JGT_X, 3, 4, 0, 0), Label::Drop);
    }

    pub(super) fn tcp_pending(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_W, 0, 10, DEVICE, 0));
        let ordinary = ahead(b, JEQ_K, 0, 0, 0);
        bank_lock(b, true);
        find_entry(b);
        b.emit(Insn::new(ST_W, 10, 0, GOOD, 0));
        let absent = ahead(b, JEQ_K, 5, 0, 0);
        b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
        let changed = ahead(b, JNE_K, 0, 0, HOST_SOCKET_CANDIDATE as i32);
        b.emit(Insn::new(LDX_DW, 0, 5, 40, 0));
        b.emit(Insn::new(LDX_DW, 1, 10, E + 40, 0));
        let replaced = ahead(b, JNE_X, 0, 1, 0);
        begin_write(b, Label::Drop);
        b.emit(Insn::new(ST_W, 5, 0, 52, HOST_SOCKET_TRANSITION as i32));
        end_write(b);
        b.emit(Insn::new(ST_W, 10, 0, GOOD, 1));
        patch(b, absent);
        patch(b, changed);
        patch(b, replaced);
        bank_lock(b, false);
        require(b, LDX_W, 10, GOOD, 1);
        b.emit(Insn::new(LDX_DW, 0, 10, E + 40, 0));
        b.emit(Insn::new(STX_DW, 10, 0, TOKEN, 0));
        self.transition(b);
        self.pending(b);
        self.restore_bank(b);
        patch(b, ordinary);
    }

    pub(super) fn commit_choice(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_W, 0, 10, CHOICE, 0));
        b.emit(Insn::new(STX_W, 5, 0, 52, 0));
        b.emit(Insn::new(ST_W, 10, 0, TRANSITION, 0));
        b.emit(Insn::new(ST_W, 10, 0, SOURCE_INSERTED, 0));
        b.emit(Insn::new(ST_W, 10, 0, PENDING_RESERVED, 0));
    }

    pub(super) fn transition(&self, b: &mut Builder) {
        b.emit(Insn::new(ST_W, 10, 0, TRANSITION, 1));
        b.emit(Insn::new(STX_DW, 10, 8, SOURCE_SOCKET, 0));
        copy(b, 10, M + 104, 10, TOKEN, 8);
    }

    pub(super) fn pending(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_DW, 0, 10, TOKEN, 0));
        b.emit(Insn::new(LDX_W, 1, 10, E + 52, 0));
        let existing_native = ahead(b, JEQ_K, 1, 0, HOST_SOCKET_NATIVE as i32);
        let existing_endpoint = ahead(b, JEQ_K, 1, 0, HOST_SOCKET_ENDPOINT as i32);
        let fresh = ahead(b, JA, 0, 0, 0);
        patch(b, existing_native);
        patch(b, existing_endpoint);
        b.emit(Insn::new(LDX_DW, 0, 10, E + 40, 0));
        patch(b, fresh);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(STX_DW, 10, 0, M + 104, 0));
        b.emit(Insn::new(LDX_DW, 6, 10, NSCRATCH, 0));
        zero(b, 6, VALUE, 72);
        b.emit(Insn::new(LDX_DW, 0, 10, OPEN_EPOCH, 0));
        b.emit(Insn::new(STX_DW, 6, 0, VALUE, 0));
        b.emit(Insn::new(STX_DW, 6, 0, VALUE + 8, 0));
        b.emit(Insn::new(LDX_DW, 0, 10, M + 104, 0));
        b.emit(Insn::new(STX_DW, 6, 0, VALUE + 48, 0));
        imm(b, 0, self.owner.scope);
        b.emit(Insn::new(STX_DW, 6, 0, VALUE + 16, 0));
        copy(b, 6, VALUE + 40, 10, M + 48, 8);
        imm(b, 0, self.source().attachment);
        b.emit(Insn::new(STX_DW, 6, 0, VALUE + 56, 0));
        b.emit(Insn::new(CALL, 0, 0, 0, 5));
        b.emit(Insn::new(LDX_DW, 6, 10, NSCRATCH, 0));
        b.emit(Insn::new(STX_DW, 6, 0, VALUE + 32, 0));
        b.emit(Insn::new(
            ST_W,
            6,
            0,
            VALUE + 24,
            NATIVE_EXECUTOR_PENDING as i32,
        ));
        b.emit(Insn::new(
            ST_W,
            6,
            0,
            VALUE + 28,
            (NATIVE_PHASE_SOURCE_PENDING | (1 << 4)) as i32,
        ));
        b.emit(Insn::new(
            0x72,
            10,
            0,
            NKEY + 38,
            NATIVE_DOMAIN_UNBOUND_SOURCE as i32,
        ));
        self.insert_owner(b, false, false);
        b.emit(Insn::new(ST_W, 10, 0, PENDING_RESERVED, 1));
        b.emit(Insn::new(LDX_DW, 6, 10, NSCRATCH, 0));
        b.emit(Insn::new(LDX_W, 0, 10, CHOICE, 0));
        let endpoint = ahead(b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
        b.emit(Insn::new(
            ST_W,
            6,
            0,
            VALUE + 24,
            NATIVE_EXECUTOR_KERNEL as i32,
        ));
        b.emit(Insn::new(ST_W, 6, 0, VALUE + 28, NATIVE_PHASE_ARMED as i32));
        copy(b, 6, VALUE + 64, 10, MARK_KIND, 8);
        let chosen = ahead(b, JA, 0, 0, 0);
        patch(b, endpoint);
        b.emit(Insn::new(
            ST_W,
            6,
            0,
            VALUE + 24,
            NATIVE_EXECUTOR_CAPTURE as i32,
        ));
        b.emit(Insn::new(
            ST_W,
            6,
            0,
            VALUE + 28,
            NATIVE_PHASE_CAPTURE_COMMITTED as i32,
        ));
        patch(b, chosen);
        b.emit(Insn::new(
            0x72,
            10,
            0,
            NKEY + 38,
            NATIVE_DOMAIN_SOURCE as i32,
        ));
        self.insert_owner(b, true, true);
    }

    fn insert_owner(&self, b: &mut Builder, selected: bool, track: bool) {
        b.map_fd(self.maps.claims);
        stack(b, 2, NKEY);
        b.emit(Insn::new(LDX_DW, 3, 10, NSCRATCH, 0));
        b.emit(Insn::new(ADD_K, 3, 0, 0, VALUE as i32));
        b.emit(Insn::new(MOV_K, 4, 0, 0, 1));
        b.emit(Insn::new(CALL, 0, 0, 0, 2));
        let inserted = ahead(b, JEQ_K, 0, 0, 0);
        b.jump(Insn::new(JNE32_K, 0, 0, 0, -libc::EEXIST), Label::Drop);
        lookup(b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(b, 6, Label::Drop);
        if selected {
            b.emit(Insn::new(LDX_DW, 1, 10, NSCRATCH, 0));
            b.emit(Insn::new(LDX_DW, 0, 6, 24, 0));
            b.emit(Insn::new(LDX_DW, 2, 1, VALUE + 24, 0));
            let same = ahead(b, 0x1d, 0, 2, 0);
            require(b, LDX_B, 10, NKEY + 38, NATIVE_DOMAIN_SOURCE as i32);
            require(b, LDX_W, 6, 24, NATIVE_EXECUTOR_KERNEL as i32);
            require(b, LDX_W, 6, 28, NATIVE_PHASE_ACTIVE as i32);
            require(b, LDX_W, 1, VALUE + 24, NATIVE_EXECUTOR_KERNEL as i32);
            require(b, LDX_W, 1, VALUE + 28, NATIVE_PHASE_ARMED as i32);
            patch(b, same);
        } else {
            require(b, LDX_W, 6, 64, ROUTING_MARK_KEEP as i32);
            require(b, LDX_W, 6, 68, 0);
            self.reserve_pending(b);
        }
        if track {
            b.emit(Insn::new(ST_W, 10, 0, SOURCE_INSERTED, 2));
        }
        let existing = ahead(b, JA, 0, 0, 0);
        patch(b, inserted);
        if track {
            b.emit(Insn::new(ST_W, 10, 0, SOURCE_INSERTED, 1));
        }
        patch(b, existing);
    }

    fn transition_entry(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_DW, 6, 10, SAVED_BANK, 0));
        b.emit(Insn::new(LDX_DW, 7, 10, M + 48, 0));
        b.emit(Insn::new(LDX_DW, 8, 10, SOURCE_SOCKET, 0));
        bank_lock(b, true);
        find_entry(b);
        let missing = ahead(b, JEQ_K, 5, 0, 0);
        b.emit(Insn::new(LDX_W, 0, 5, 52, 0));
        let changed = ahead(b, JNE_K, 0, 0, HOST_SOCKET_TRANSITION as i32);
        b.emit(Insn::new(LDX_DW, 0, 5, 40, 0));
        b.emit(Insn::new(LDX_DW, 1, 10, TOKEN, 0));
        let replaced = ahead(b, JNE_X, 0, 1, 0);
        let owned = ahead(b, JA, 0, 0, 0);
        for at in [missing, changed, replaced] {
            patch(b, at);
        }
        bank_lock(b, false);
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Fragments);
        patch(b, owned);
    }

    fn rollback(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_W, 0, 10, TRANSITION, 0));
        let frozen = ahead(b, JEQ_K, 0, 0, 0);
        self.transition_entry(b);
        bank_lock(b, false);
        b.emit(Insn::new(LDX_W, 0, 10, SOURCE_INSERTED, 0));
        let no_source = ahead(b, JEQ_K, 0, 0, 0);
        // EEXIST establishes identity, never this invocation's deletion authority.
        b.jump(Insn::new(JNE_K, 0, 0, 0, 1), Label::Fragments);
        b.emit(Insn::new(
            0x72,
            10,
            0,
            NKEY + 38,
            NATIVE_DOMAIN_SOURCE as i32,
        ));
        lookup(b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Fragments);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(b, 6, Label::Fragments);
        b.emit(Insn::new(LDX_DW, 1, 10, NSCRATCH, 0));
        same64(b, 6, 24, 1, VALUE + 24, Label::Fragments);
        b.map_fd(self.maps.claims);
        stack(b, 2, NKEY);
        b.emit(Insn::new(CALL, 0, 0, 0, 3));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Fragments);
        b.emit(Insn::new(ST_W, 10, 0, SOURCE_INSERTED, 0));
        patch(b, no_source);
        patch(b, frozen);
        b.emit(Insn::new(LDX_W, 0, 10, PENDING_RESERVED, 0));
        let no_pending = ahead(b, JEQ_K, 0, 0, 0);
        b.emit(Insn::new(
            0x72,
            10,
            0,
            NKEY + 38,
            NATIVE_DOMAIN_UNBOUND_SOURCE as i32,
        ));
        lookup(b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Fragments);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(b, 6, Label::Fragments);
        self.complete_pending(b, Label::Fragments);
        b.emit(Insn::new(ST_W, 10, 0, PENDING_RESERVED, 0));
        patch(b, no_pending);
        b.emit(Insn::new(LDX_W, 0, 10, TRANSITION, 0));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Fragments);
        self.transition_entry(b);
        begin_write(b, Label::Fragments);
        // Restore only selection ownership; concurrent optional process facts remain intact.
        copy(b, 5, 40, 10, E + 40, 8);
        copy(b, 5, 52, 10, E + 52, 4);
        end_write(b);
        bank_lock(b, false);
    }

    pub(super) fn end(&self, b: &mut Builder, rollback: bool) {
        b.label(Label::Drop);
        if rollback {
            self.rollback(b);
        }
        b.label(Label::Fragments);
        self.release_scratch(b);
        b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        b.label(Label::Pass);
        self.release_scratch(b);
        b.emit(Insn::new(MOV_K, 0, 0, 0, 1));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
    }
    fn release_scratch(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_DW, 1, 10, NSCRATCH, 0));
        let absent = ahead(b, JEQ_K, 1, 0, 0);
        b.emit(Insn::new(ST_W, 1, 0, S_BUSY, 0));
        patch(b, absent);
    }
    pub(super) fn finish(&self, mut p: Program) -> io::Result<Program> {
        if p.len > WRAPPER_INSNS {
            return Err(invalid_data(
                "Host wrapper exceeds charged instruction ceiling",
            ));
        }
        let calls: Vec<usize> = p
            .insns
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                (v.code == CALL && v.regs >> 4 == 1 && v.imm == CANONICAL_CALL).then_some(i)
            })
            .collect();
        if !calls.is_empty() {
            let bytecode = self.policy().bytecode;
            if bytecode
                .iter()
                .any(|insn| insn.dst_reg() == 10 || insn.src_reg() == 10)
            {
                return Err(invalid_data(
                    "Host canonical code requires map-backed temporary storage",
                ));
            }
            if p.len
                .checked_add(bytecode.len())
                .is_none_or(|n| n > MAX_PROGRAM_INSNS)
            {
                return Err(invalid_data(
                    "Host canonical program exceeds instruction ceiling",
                ));
            }
            let body = p.len;
            p.insns
                .try_reserve_exact(bytecode.len())
                .map_err(io::Error::other)?;
            for at in calls {
                p.insns[at].imm =
                    i32::try_from(body as isize - at as isize - 1).map_err(io::Error::other)?;
            }
            for i in bytecode {
                p.insns
                    .push(Insn::new(i.code, i.dst_reg(), i.src_reg(), i.off, i.imm));
            }
            p.len = p.insns.len();
        }
        Ok(p)
    }
}

impl Selection<'_> {
    fn read_bank(&self, b: &mut Builder) {
        b.emit(Insn::new(MOV_X, 0, 7, 0, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, (HOST_SOCKET_BUCKETS - 1) as i32));
        b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
        lookup(b, self.maps.source.sockets, KEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        b.emit(Insn::new(STX_DW, 10, 6, SAVED_BANK, 0));
        b.emit(Insn::new(LDX_DW, 0, 6, 0, 0));
        b.emit(Insn::new(STX_DW, 10, 0, BANK_VERSION, 0));
        b.jump(Insn::new(0x45, 0, 0, 0, 1), Label::Drop);
        zero(b, 10, E, 64);
        find_entry(b);
        let absent = ahead(b, JEQ_K, 5, 0, 0);
        copy(b, 10, E, 5, 0, 64);
        patch(b, absent);
        same64(b, 6, 0, 10, BANK_VERSION, Label::Drop);
        require(b, LDX_W, 10, E + 60, 0);
        b.emit(Insn::new(LDX_W, 0, 10, E + 36, 0));
        b.emit(Insn::new(
            AND_K,
            0,
            0,
            0,
            !(HOST_SOCKET_PROCESS_PRESENT as i32),
        ));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        b.jump(
            Insn::new(JGT_K, 0, 0, 0, HOST_SOCKET_NATIVE as i32),
            Label::Drop,
        );
        b.emit(Insn::new(LDX_DW, 0, 10, E + 40, 0));
        b.emit(Insn::new(STX_DW, 10, 0, M + 104, 0));
    }

    /// No orig_ops dereference: unregister may leave priv while replacing callback with accept_all.
    fn live_registration(&self, b: &mut Builder) {
        const HOOKS: i16 = -384;
        const COUNT: i16 = -376;
        const FOUND: i16 = -372;
        b.emit(Insn::new(LDX_DW, 6, 10, NET, 0));
        let hook_array = if self.owner.family == libc::AF_INET as u8 {
            self.layout().net_hooks_ipv4
        } else {
            self.layout().net_hooks_ipv6
        };
        read_kernel(b, 6, hook_array + LOCAL_OUT * 8, 8, HOOKS, Label::Drop);
        b.emit(Insn::new(LDX_DW, 6, 10, HOOKS, 0));
        b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Drop);
        zero(b, 10, COUNT, 8);
        read_kernel(b, 6, self.layout().hooks_count, 2, COUNT, Label::Drop);
        b.emit(Insn::new(LDX_H, 0, 10, COUNT, 0));
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.jump(Insn::new(JGT_K, 0, 0, 0, 64), Label::Drop);
        b.emit(Insn::new(MOV_X, 8, 0, 0, 0));
        b.emit(Insn::new(MOV_K, 7, 0, 0, 0));
        let loop_start = b.program.len;
        b.emit(Insn::new(LDX_DW, 6, 10, HOOKS, 0));
        b.emit(Insn::new(MOV_X, 0, 7, 0, 0));
        b.emit(Insn::new(LSH_K, 0, 0, 0, 4));
        b.emit(Insn::new(ADD_X, 6, 0, 0, 0));
        b.emit(Insn::new(
            ADD_K,
            6,
            0,
            0,
            self.layout().hooks_entries as i32,
        ));
        read_kernel(b, 6, self.layout().hook_callback, 8, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_DW, 0, 10, SCRATCH, 0));
        imm(b, 1, self.layout().producer_callback);
        let unrelated = ahead(b, JNE_X, 0, 1, 0);
        read_kernel(b, 6, self.layout().hook_private, 8, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_DW, 6, 10, SCRATCH, 0));
        b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Drop);
        read_kernel(b, 6, self.layout().prog_aux, 8, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_DW, 6, 10, SCRATCH, 0));
        b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Drop);
        read_kernel(b, 6, self.layout().aux_id, 4, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_W, 0, 10, SCRATCH, 0));
        let other_program = ahead(b, JNE32_K, 0, 0, self.producer_id as i32);
        b.emit(Insn::new(LDX_W, 0, 10, FOUND, 0));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(ST_W, 10, 0, FOUND, 1));
        patch(b, other_program);
        patch(b, unrelated);
        b.emit(Insn::new(ADD_K, 7, 0, 0, 1));
        let back = b.program.len;
        b.emit(Insn::new(
            0xad,
            7,
            8,
            (loop_start as isize - back as isize - 1) as i16,
            0,
        ));
        require(b, LDX_W, 10, FOUND, 1);
    }

    fn final_frontier(&self, b: &mut Builder) {
        copy(b, 10, TOKEN, 10, M + 104, 8);
        b.emit(Insn::new(LDX_DW, 1, 10, ROOT_POINTER, 0));
        b.emit(Insn::new(LDX_DW, 0, 10, OPEN_EPOCH, 0));
        b.emit(Insn::new(MOV_X, 2, 0, 0, 0));
        b.emit(Insn::new(ATOMIC_ADD_DW, 1, 2, 0, 0xf1));
        b.jump(Insn::new(JNE_X, 0, 2, 0, 0), Label::Drop);
        b.emit(Insn::new(CALL, 0, 0, 0, 125));
        imm(b, 1, self.policy().expires_boottime_ns);
        b.jump(Insn::new(JGE_X, 0, 1, 0, 0), Label::Drop);
        gate(b, self.maps.source.gate);
        require(b, LDX_W, 10, READY, 1);
        // Revalidate the source after the admission RMW, without a helper under a bank lock.
        self.restore_bank(b);
        self.read_bank(b);
        same64(b, 10, E + 40, 10, TOKEN, Label::Drop);
        require(b, LDX_W, 10, E + 52, HOST_SOCKET_NATIVE as i32);
        self.live_registration(b);
    }

    fn matcher(&self, action: Option<Option<u32>>) -> io::Result<Program> {
        let mut b = Builder::new();
        b.reserve(
            WRAPPER_INSNS
                .checked_add(if action.is_some() {
                    self.policy().bytecode.len()
                } else {
                    0
                })
                .ok_or_else(|| invalid_data("Host matcher instruction reservation overflow"))?,
        )?;
        b.emit(Insn::new(MOV_X, 9, 1, 0, 0));
        zero(&mut b, 10, M, 128);
        b.emit(Insn::new(0x7a, 10, 0, NSCRATCH, 0));
        b.emit(Insn::new(0x7a, 10, 0, TOKEN, 0));
        b.emit(Insn::new(MOV_X, 1, 9, 0, 0));
        b.emit(Insn::new(CALL, 0, 2, 0, self.layout().cast as i32));
        b.emit(Insn::new(STX_DW, 10, 0, KSKB, 0));
        self.socket_origin(&mut b, true);
        self.read_bank(&mut b);
        if action.is_none() {
            b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
            b.jump(
                Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_ENDPOINT as i32),
                Label::Pass,
            );
            b.jump(
                Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_KERNEL as i32),
                Label::Pass,
            );
            b.jump(
                Insn::new(JEQ_K, 0, 0, 0, HOST_SOCKET_NATIVE as i32),
                Label::Selected,
            );
            b.emit(Insn::new(LDX_W, 1, 10, M + 72, 0));
            b.jump(
                Insn::new(JEQ32_K, 1, 0, 0, self.source().bypass_mark as i32),
                Label::Pass,
            );
            b.emit(Insn::new(LDX_W, 1, 10, PROTOCOL, 0));
            let udp = ahead(&mut b, JEQ_K, 1, 0, 17);
            let candidate = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_CANDIDATE as i32);
            b.jump(
                Insn::new(JNE_K, 0, 0, 0, HOST_SOCKET_TRANSITION as i32),
                Label::Pass,
            );
            patch(&mut b, udp);
            patch(&mut b, candidate);
            b.emit(Insn::new(LDX_W, 0, 10, M + 64, 0));
            b.emit(Insn::new(STX_W, 10, 0, KEY, 0));
            lookup(&mut b, self.maps.source.returns, KEY);
            b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Pass);
            b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
            require(&mut b, LDX_W, 6, 12, 0);
            require(&mut b, LDX_W, 6, 28, 0);
            b.emit(Insn::new(LDX_W, 0, 6, 8, 0));
            b.emit(Insn::new(LDX_W, 1, 10, KEY, 0));
            b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
            b.label(Label::Selected);
            // True means the trailing nft DROP applies, including absent/dead producer registration.
            b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
            b.label(Label::Pass);
            b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
            b.emit(Insn::new(EXIT, 0, 0, 0, 0));
            b.label(Label::Drop);
            b.emit(Insn::new(MOV_K, 0, 0, 0, 1));
            b.emit(Insn::new(EXIT, 0, 0, 0, 0));
            return b.finish();
        }
        require(&mut b, LDX_W, 10, E + 52, HOST_SOCKET_NATIVE as i32);
        self.root(&mut b);
        self.packet_key(&mut b);
        self.acquire_scratch(&mut b);
        lookup(&mut b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(&mut b, 6, Label::Drop);
        require(&mut b, LDX_W, 6, 24, NATIVE_EXECUTOR_KERNEL as i32);
        self.native_phase(&mut b, 6);
        let armed = ahead(&mut b, JEQ_K, 0, 0, NATIVE_PHASE_ARMED as i32);
        b.emit(Insn::new(LDX_W, 0, 10, PROTOCOL, 0));
        let tcp = ahead(&mut b, JNE_K, 0, 0, 17);
        let mut dns = Vec::with_capacity(2);
        for off in [32, 34] {
            b.emit(Insn::new(LDX_H, 0, 10, NKEY + off, 0));
            dns.push(ahead(&mut b, JEQ_K, 0, 0, 53u16.to_be() as i32));
        }
        patch(&mut b, tcp);
        self.retained_effect(&mut b, 6);
        b.emit(Insn::new(ST_W, 10, 0, CHOICE, HOST_SOCKET_NATIVE as i32));
        let frozen = ahead(&mut b, JA, 0, 0, 0);
        patch(&mut b, armed);
        for at in dns {
            patch(&mut b, at);
        }
        self.canonical(&mut b);
        self.decide(&mut b);
        patch(&mut b, frozen);
        require(&mut b, LDX_W, 10, CHOICE, HOST_SOCKET_NATIVE as i32);
        let mark = action.unwrap();
        require(
            &mut b,
            LDX_W,
            10,
            MARK_KIND,
            if mark.is_some() {
                ROUTING_MARK_SET
            } else {
                ROUTING_MARK_KEEP
            } as i32,
        );
        require(&mut b, LDX_W, 10, MARK_VALUE, mark.unwrap_or(0) as i32);
        self.final_frontier(&mut b);
        self.activate_source(&mut b);
        self.refresh_activity(&mut b);
        self.release_scratch(&mut b);
        b.emit(Insn::new(MOV_K, 0, 0, 0, 1));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        b.label(Label::Drop);
        self.release_scratch(&mut b);
        b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        b.label(Label::Pass);
        b.emit(Insn::new(MOV_K, 0, 0, 0, 0));
        b.emit(Insn::new(EXIT, 0, 0, 0, 0));
        self.finish(b.finish()?)
    }

    fn refresh_activity(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_W, 0, 10, RETAINED, 0));
        let ordinary = ahead(b, JEQ_K, 0, 0, 0);
        b.emit(Insn::new(LDX_W, 0, 10, PROTOCOL, 0));
        let tcp = ahead(b, JNE_K, 0, 0, 17);
        lookup(b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(b, 6, Label::Drop);
        b.emit(Insn::new(CALL, 0, 0, 0, 5));
        b.emit(Insn::new(MOV_X, 2, 0, 0, 0));
        b.emit(Insn::new(LDX_DW, 0, 6, 32, 0));
        let mut done = Vec::with_capacity(8);
        for _ in 0..4 {
            done.push(ahead(b, JGE_X, 0, 2, 0));
            self.udp_idle_deadline(b);
            imm(b, 4, honk_ebpf_common::xdp::NATIVE_CLAIM_UPDATE_INTERVAL_NS);
            done.push(ahead(b, JGE_X, 4, 3, 0));
            b.emit(Insn::new(MOV_X, 3, 0, 0, 0));
            b.emit(Insn::new(ATOMIC_ADD_DW, 6, 2, 32, 0xf1));
            done.push(ahead(b, 0x1d, 0, 3, 0));
        }
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
        for at in done {
            patch(b, at);
        }
        patch(b, tcp);
        patch(b, ordinary);
    }

    fn binding(&self) -> io::Result<Program> {
        let mut b = Builder::new();
        self.origin(&mut b);
        bank(
            &mut b,
            self.maps.source.sockets,
            self.maps.source.socket_locks,
        );
        snapshot(&mut b);
        b.emit(Insn::new(STX_DW, 10, 6, SAVED_BANK, 0));
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        let native = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_NATIVE as i32);
        b.jump(
            Insn::new(JNE_K, 0, 0, 0, HOST_SOCKET_ENDPOINT as i32),
            Label::Pass,
        );
        patch(&mut b, native);
        b.emit(Insn::new(LDX_DW, 0, 10, E + 40, 0));
        b.emit(Insn::new(STX_DW, 10, 0, M + 104, 0));
        self.root(&mut b);
        self.packet_key(&mut b);
        self.acquire_scratch(&mut b);
        lookup(&mut b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(&mut b, 6, Label::Drop);
        b.emit(Insn::new(LDX_W, 0, 10, E + 52, 0));
        let endpoint = ahead(&mut b, JEQ_K, 0, 0, HOST_SOCKET_ENDPOINT as i32);
        require(&mut b, LDX_W, 6, 24, NATIVE_EXECUTOR_KERNEL as i32);
        require(&mut b, LDX_W, 6, 28, NATIVE_PHASE_ACTIVE as i32);
        let selected = ahead(&mut b, JA, 0, 0, 0);
        patch(&mut b, endpoint);
        require(&mut b, LDX_W, 6, 24, NATIVE_EXECUTOR_CAPTURE as i32);
        require(&mut b, LDX_W, 6, 28, NATIVE_PHASE_CAPTURE_COMMITTED as i32);
        patch(&mut b, selected);
        b.emit(Insn::new(LDX_DW, 1, 10, NSCRATCH, 0));
        copy(&mut b, 1, VALUE, 6, 0, 72);
        self.ct_projection(&mut b);
        self.end(&mut b, false);
        b.finish()
    }

    fn ct_projection(&self, b: &mut Builder) {
        // The skb owns this reference throughout the synchronous hook; nf_ct_get does not acquire one.
        // No lookup/acquire kfunc is called, and no CT pointer or reference escapes this invocation.
        b.emit(Insn::new(LDX_DW, 6, 10, KSKB, 0));
        read_kernel(b, 6, self.layout().skb_nfct, 8, POINTER, Label::Drop);
        b.emit(Insn::new(LDX_DW, 6, 10, POINTER, 0));
        b.emit(Insn::new(MOV_X, 0, 6, 0, 0));
        b.emit(Insn::new(AND_K, 0, 0, 0, 7));
        // Null/UNTRACKED leave the negative alias intact; there is no inferred zone-zero binding.
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 7), Label::Pass);
        b.emit(Insn::new(AND_K, 6, 0, 0, -8));
        b.jump(Insn::new(JEQ_K, 6, 0, 0, 0), Label::Pass);
        b.emit(Insn::new(STX_DW, 10, 6, POINTER, 0));
        read_kernel(b, 6, self.layout().ct_status, 8, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_DW, 0, 10, SCRATCH, 0));
        b.jump(Insn::new(0x45, 0, 0, 0, (1 << 9) | (1 << 11)), Label::Pass);
        read_kernel(b, 6, self.layout().ct_net, 8, SCRATCH, Label::Drop);
        same64(b, 10, SCRATCH, 10, NET, Label::Drop);
        read_kernel(b, 6, self.layout().ct_zone_flags, 1, SCRATCH, Label::Drop);
        require(b, LDX_B, 10, SCRATCH, 0);
        read_kernel(b, 6, self.layout().ct_zone_dir, 1, GOOD, Label::Drop);
        b.emit(Insn::new(LDX_B, 0, 10, GOOD, 0));
        b.jump(Insn::new(JGT_K, 0, 0, 0, 3), Label::Drop);
        read_kernel(b, 6, self.layout().ct_zone_id, 2, TOKEN, Label::Drop);
        // Keep the exact pre-CT unbound key until both actual-direction aliases are committed.
        b.emit(Insn::new(LDX_DW, 1, 10, NSCRATCH, 0));
        copy(b, 1, S_INPUT, 10, NKEY, 56);
        for (offset, dest, bytes) in [
            (self.layout().ct_src, NKEY, 16),
            (self.layout().ct_dst, NKEY + 16, 16),
        ] {
            read_kernel(b, 6, offset, bytes, dest, Label::Drop);
        }
        read_kernel(b, 6, self.layout().ct_family, 2, SCRATCH, Label::Drop);
        b.emit(Insn::new(LDX_H, 0, 10, SCRATCH, 0));
        let v6 = ahead(b, JEQ_K, 0, 0, libc::AF_INET6);
        b.jump(Insn::new(JNE_K, 0, 0, 0, libc::AF_INET), Label::Drop);
        for base in [NKEY, NKEY + 16] {
            b.emit(Insn::new(LDX_W, 0, 10, base, 0));
            zero(b, 10, base, 12);
            b.emit(Insn::new(
                ST_W,
                10,
                0,
                base + 8,
                u32::from_ne_bytes([0, 0, 255, 255]) as i32,
            ));
            b.emit(Insn::new(STX_W, 10, 0, base + 12, 0));
        }
        b.emit(Insn::new(0x72, 10, 0, NKEY + 37, 4));
        let family = ahead(b, JA, 0, 0, 0);
        patch(b, v6);
        b.emit(Insn::new(0x72, 10, 0, NKEY + 37, 6));
        patch(b, family);
        for (offset, dest) in [
            (self.layout().ct_sport, NKEY + 32),
            (self.layout().ct_dport, NKEY + 34),
        ] {
            read_kernel(b, 6, offset, 2, dest, Label::Drop);
        }
        read_kernel(b, 6, self.layout().ct_protocol, 1, NKEY + 36, Label::Drop);
        b.emit(Insn::new(LDX_B, 0, 10, NKEY + 36, 0));
        b.emit(Insn::new(LDX_W, 1, 10, PROTOCOL, 0));
        b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
        b.emit(Insn::new(0x72, 10, 0, NKEY + 38, NATIVE_DOMAIN_FLOW as i32));
        b.emit(Insn::new(
            0x72,
            10,
            0,
            NKEY + 50,
            NATIVE_ZONE_BOUND_ACTUAL as i32,
        ));
        for direction in 0..2 {
            b.emit(Insn::new(0x72, 10, 0, NKEY + 39, direction));
            b.emit(Insn::new(ST_H, 10, 0, NKEY + 48, 0));
            b.emit(Insn::new(LDX_B, 0, 10, GOOD, 0));
            b.emit(Insn::new(AND_K, 0, 0, 0, 1 << direction));
            let default_zone = ahead(b, JEQ_K, 0, 0, 0);
            b.emit(Insn::new(LDX_H, 0, 10, TOKEN, 0));
            b.emit(Insn::new(STX_H, 10, 0, NKEY + 48, 0));
            patch(b, default_zone);
            self.insert_owner(b, true, false);
        }
        b.emit(Insn::new(LDX_DW, 6, 10, NSCRATCH, 0));
        copy(b, 10, NKEY, 6, S_INPUT, 56);
        b.emit(Insn::new(
            0x72,
            10,
            0,
            NKEY + 38,
            NATIVE_DOMAIN_UNBOUND_SOURCE as i32,
        ));
        lookup(b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(b, 6, Label::Drop);
        self.complete_pending(b, Label::Drop);
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Pass);
    }
}

#[repr(C)]
#[derive(Default)]
struct MapInfo {
    kind: u32,
    id: u32,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
}

fn admit_map(fd: BorrowedFd<'_>, kind: u32, key: u32, value: u32) -> io::Result<()> {
    let mut info = MapInfo::default();
    object_info(fd, &mut info)?;
    if info.kind != kind
        || info.id == 0
        || info.key != key
        || info.value != value
        || info.entries == 0
        || info.flags != 0
    {
        return Err(invalid_data("Host Native shared map ABI mismatch"));
    }
    Ok(())
}
fn map_id(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut info = MapInfo::default();
    object_info(fd, &mut info)?;
    if info.id == 0 {
        return Err(invalid_data("Host Native map has no identity"));
    }
    Ok(info.id)
}
fn map_id_raw(fd: RawFd) -> io::Result<u32> {
    if fd < 0 {
        return Err(invalid_data("Host Native map descriptor missing"));
    }
    // The NativeProgramConfig borrows these descriptors for the complete prepare call.
    map_id(unsafe { BorrowedFd::borrow_raw(fd) })
}
fn require_closed(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let root: NativeRoot = map_value(fd, &0u32)?;
    if root.epoch & 1 != 0 || root.reserved != 0 {
        return Err(invalid_data(
            "Host mutation requires the same closed Native publication",
        ));
    }
    Ok(root.epoch)
}

fn validate_actions(actions: &[Option<u32>]) -> io::Result<()> {
    if actions.is_empty()
        || actions.len() > MAX_ACTIONS
        || actions.iter().filter(|v| v.is_some()).count() > 256
        || actions.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(invalid_data(
            "Host actions must be sorted unique Keep/Set effects, at most 257",
        ));
    }
    Ok(())
}

fn validate_config(c: &HostNativeConfig, btf: &Btf) -> io::Result<()> {
    let l = &c.layout;
    let s = &c.source;
    if !cfg!(all(target_arch = "x86_64", target_endian = "little"))
        || ![libc::AF_INET as u8, libc::AF_INET6 as u8].contains(&c.family)
        || s.source_netns == 0
        || s.attachment == 0
        || c.scope == 0
        || s.sock_wfree == 0
        || s.bypass_mark == 0
        || s.bypass_mark & honk_ebpf_common::CLASSIFIED_MARK != 0
        || l.producer_callback == 0
        || l.cast == 0
        || l.hook_stride != 16
        || l.hook_callback != 0
        || l.hook_private != 8
        || l.hooks_entries != 8
        || l.hooks_count != 0
    {
        return Err(invalid_data(
            "unadmitted Host Native source/registration layout",
        ));
    }
    let cast = btf
        .id_by_type_name_kind("bpf_cast_to_kern_ctx", BtfKind::Func)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Host Native actual skb cast: {e}"),
            )
        })?;
    if cast != l.cast {
        return Err(invalid_data(
            "Host Native cast differs from admitted running BTF",
        ));
    }
    let offsets = [
        l.sock_cookie,
        l.sock_family,
        l.sock_state,
        l.sock_type,
        l.sock_protocol,
        l.sock_mark,
        l.skb_len,
        l.skb_data_len,
        l.skb_data,
        l.skb_protocol,
        l.skb_mark,
        l.skb_refdst,
        l.skb_nfct,
        l.dst_dev,
        l.dev_ifindex,
        l.dev_net,
        l.state_net,
        l.state_out,
        l.state_hook,
        l.state_pf,
        l.ct_net,
        l.ct_status,
        l.ct_zone_id,
        l.ct_zone_dir,
        l.ct_zone_flags,
        l.ct_src,
        l.ct_dst,
        l.ct_sport,
        l.ct_dport,
        l.ct_family,
        l.ct_protocol,
        l.net_hooks_ipv4,
        l.net_hooks_ipv6,
        l.prog_aux,
        l.aux_id,
        s.skb_sk_offset,
        s.sock_net_pointer_offset,
        s.net_cookie_offset,
        s.skb_destructor_offset,
        s.skb_truesize_offset,
        s.sock_wmem_offset,
        s.sock_refcnt_offset,
        s.sock_write_queue_len_offset,
    ];
    if offsets.iter().any(|v| *v > i32::MAX as u32 - 1024) {
        return Err(invalid_data(
            "Host Native BTF offset exceeds bounded kernel read",
        ));
    }
    Ok(())
}

#[repr(C)]
#[derive(Default)]
struct ProgramMemoryInfo {
    kind: u32,
    id: u32,
    tag: [u8; 8],
    jited: u32,
    translated: u32,
}
fn load(p: &Program, name: &[u8], kind: u32, attach: u32, log: &mut [u8]) -> io::Result<Loaded> {
    if p.len > MAX_PROGRAM_INSNS {
        return Err(invalid_data("Host Native instruction ceiling exceeded"));
    }
    let (fd, id) = load_typed_program(p, name, log, kind, attach)?;
    let mut info = ProgramMemoryInfo::default();
    object_info(fd.as_fd(), &mut info)?;
    if info.id != id
        || info.kind != kind
        || info.translated == 0
        || info.translated as usize > PROGRAM_LIMIT
        || info.jited as usize > PROGRAM_LIMIT
    {
        return Err(invalid_data(
            "Host Native translated/JIT program allocation exceeds admission",
        ));
    }
    let formula = (info.translated as usize)
        .checked_mul(3)
        .and_then(|v| v.checked_add(info.jited as usize))
        .and_then(|v| v.checked_add(8192))
        .ok_or_else(|| invalid_data("Host Native program charge overflow"))?;
    let reported = usize::try_from(fd_memlock(fd.as_fd())?).map_err(io::Error::other)?;
    if info.translated as usize > p.len.saturating_mul(16)
        || formula.max(reported) > program_upper(p.len)?
    {
        return Err(invalid_data(
            "Host actual program allocation exceeds its pre-load reservation",
        ));
    }
    Ok(Loaded {
        fd,
        id,
        memory: formula.max(reported),
    })
}

#[repr(C)]
struct NfLinkCreate {
    program: u32,
    target: u32,
    attach: u32,
    flags: u32,
    family: u32,
    hook: u32,
    priority: i32,
    netfilter_flags: u32,
}
#[repr(C)]
#[derive(Default)]
struct NfLinkInfo {
    kind: u32,
    id: u32,
    program: u32,
    padding: u32,
    family: u32,
    hook: u32,
    priority: i32,
    flags: u32,
}
fn attach(program: BorrowedFd<'_>, family: u8, priority: i32) -> io::Result<(OwnedFd, u32)> {
    let mut attr = NfLinkCreate {
        program: program.as_raw_fd() as u32,
        target: 0,
        attach: NETFILTER_ATTACH,
        flags: 0,
        family: family as u32,
        hook: LOCAL_OUT,
        priority,
        netfilter_flags: 0,
    };
    let fd = bpf_fd(BPF_LINK_CREATE, &mut attr)?;
    let mut info = NfLinkInfo::default();
    object_info(fd.as_fd(), &mut info)?;
    let mut p = ProgInfo::default();
    object_info(program, &mut p)?;
    check_link(
        fd.as_fd(),
        HostNativeHook {
            family,
            hook: LOCAL_OUT,
            priority,
            flags: 0,
            program_id: p.id,
            link_id: info.id,
        },
    )?;
    Ok((fd, info.id))
}
fn check_link(fd: BorrowedFd<'_>, expected: HostNativeHook) -> io::Result<()> {
    let mut info = NfLinkInfo::default();
    object_info(fd, &mut info)?;
    if info.kind != 10
        || info.id == 0
        || info.id != expected.link_id
        || info.program != expected.program_id
        || info.family != expected.family as u32
        || info.hook != expected.hook
        || info.priority != expected.priority
        || info.flags != expected.flags
    {
        return Err(invalid_data(
            "Host Native actual NETFILTER link identity mismatch",
        ));
    }
    Ok(())
}

fn program_upper(insns: usize) -> io::Result<usize> {
    let translated = insns
        .checked_mul(16)
        .filter(|v| *v <= PROGRAM_LIMIT)
        .ok_or_else(|| invalid_data("Host translated instruction bound exceeds 1MiB"))?;
    let jited = insns
        .checked_mul(256)
        .ok_or_else(|| invalid_data("Host x86 JIT bound overflow"))?
        .min(PROGRAM_LIMIT);
    translated
        .checked_mul(3)
        .and_then(|v| v.checked_add(jited))
        .and_then(|v| v.checked_add(8192))
        .ok_or_else(|| invalid_data("Host program allocation bound overflow"))
}

impl Selection<'_> {
    fn reserve_pending(&self, b: &mut Builder) {
        b.emit(Insn::new(LDX_DW, 0, 6, 24, 0));
        let mut done = Vec::with_capacity(4);
        for _ in 0..4 {
            b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
            b.emit(Insn::new(0xbc, 1, 1, 0, 0));
            b.jump(
                Insn::new(JNE_K, 1, 0, 0, NATIVE_EXECUTOR_PENDING as i32),
                Label::Drop,
            );
            b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
            b.emit(Insn::new(RSH_K, 1, 0, 0, 32));
            b.emit(Insn::new(AND_K, 1, 0, 0, 15));
            b.jump(
                Insn::new(JNE_K, 1, 0, 0, NATIVE_PHASE_SOURCE_PENDING as i32),
                Label::Drop,
            );
            b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
            b.emit(Insn::new(RSH_K, 1, 0, 0, 36));
            b.jump(Insn::new(JEQ_K, 1, 0, 0, 0), Label::Drop);
            b.jump(
                Insn::new(
                    JGE_K,
                    1,
                    0,
                    0,
                    honk_ebpf_common::xdp::NATIVE_OUTSTANDING_MAX as i32,
                ),
                Label::Drop,
            );
            b.emit(Insn::new(MOV_X, 3, 0, 0, 0));
            b.emit(Insn::new(MOV_X, 2, 0, 0, 0));
            imm(b, 1, 1u64 << 36);
            b.emit(Insn::new(ADD_X, 2, 1, 0, 0));
            b.emit(Insn::new(ATOMIC_ADD_DW, 6, 2, 24, 0xf1));
            done.push(ahead(b, 0x1d, 0, 3, 0));
        }
        b.jump(Insn::new(JA, 0, 0, 0, 0), Label::Drop);
        for at in done {
            patch(b, at);
        }
    }

    fn complete_pending(&self, b: &mut Builder, failure: Label) {
        b.emit(Insn::new(LDX_DW, 0, 6, 24, 0));
        let mut decremented = Vec::with_capacity(4);
        let mut delete = Vec::with_capacity(4);
        for _ in 0..4 {
            b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
            b.emit(Insn::new(0xbc, 1, 1, 0, 0));
            b.jump(
                Insn::new(JNE_K, 1, 0, 0, NATIVE_EXECUTOR_PENDING as i32),
                failure,
            );
            b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
            b.emit(Insn::new(RSH_K, 1, 0, 0, 32));
            b.emit(Insn::new(AND_K, 1, 0, 0, 15));
            b.jump(
                Insn::new(JNE_K, 1, 0, 0, NATIVE_PHASE_SOURCE_PENDING as i32),
                failure,
            );
            b.emit(Insn::new(MOV_X, 1, 0, 0, 0));
            b.emit(Insn::new(RSH_K, 1, 0, 0, 36));
            b.jump(Insn::new(JEQ_K, 1, 0, 0, 0), failure);
            b.emit(Insn::new(MOV_X, 3, 0, 0, 0));
            b.emit(Insn::new(MOV_X, 2, 0, 0, 0));
            let last = ahead(b, JEQ_K, 1, 0, 1);
            imm(b, 1, 1u64 << 36);
            b.emit(Insn::new(0x1f, 2, 1, 0, 0));
            b.emit(Insn::new(ATOMIC_ADD_DW, 6, 2, 24, 0xf1));
            decremented.push(ahead(b, 0x1d, 0, 3, 0));
            let retry = ahead(b, JA, 0, 0, 0);
            patch(b, last);
            imm(
                b,
                2,
                u64::from(NATIVE_EXECUTOR_PENDING)
                    | (u64::from(honk_ebpf_common::xdp::NATIVE_PHASE_CLOSING) << 32),
            );
            b.emit(Insn::new(ATOMIC_ADD_DW, 6, 2, 24, 0xf1));
            delete.push(ahead(b, 0x1d, 0, 3, 0));
            patch(b, retry);
        }
        b.jump(Insn::new(JA, 0, 0, 0, 0), failure);
        for at in delete {
            patch(b, at);
        }
        b.map_fd(self.maps.claims);
        stack(b, 2, NKEY);
        b.emit(Insn::new(CALL, 0, 0, 0, 3));
        b.jump(Insn::new(JNE_K, 0, 0, 0, 0), failure);
        for at in decremented {
            patch(b, at);
        }
    }
}
impl Selection<'_> {
    fn native_phase(&self, b: &mut Builder, reg: u8) {
        b.emit(Insn::new(LDX_W, 0, reg, 28, 0));
        let active = ahead(b, JEQ_K, 0, 0, NATIVE_PHASE_ACTIVE as i32);
        b.jump(
            Insn::new(JNE_K, 0, 0, 0, NATIVE_PHASE_ARMED as i32),
            Label::Drop,
        );
        same64(b, reg, 0, 10, OPEN_EPOCH, Label::Drop);
        patch(b, active);
        b.emit(Insn::new(LDX_W, 0, reg, 28, 0));
    }

    fn activate_source(&self, b: &mut Builder) {
        lookup(b, self.maps.claims, NKEY);
        b.jump(Insn::new(JEQ_K, 0, 0, 0, 0), Label::Drop);
        b.emit(Insn::new(MOV_X, 6, 0, 0, 0));
        self.source_identity(b, 6, Label::Drop);
        b.emit(Insn::new(LDX_DW, 0, 6, 24, 0));
        imm(
            b,
            1,
            u64::from(NATIVE_EXECUTOR_KERNEL) | (u64::from(NATIVE_PHASE_ACTIVE) << 32),
        );
        let active = ahead(b, 0x1d, 0, 1, 0);
        self.first_effect(b);
        imm(
            b,
            0,
            u64::from(NATIVE_EXECUTOR_KERNEL) | (u64::from(NATIVE_PHASE_ARMED) << 32),
        );
        imm(
            b,
            2,
            u64::from(NATIVE_EXECUTOR_KERNEL) | (u64::from(NATIVE_PHASE_ACTIVE) << 32),
        );
        b.emit(Insn::new(MOV_X, 3, 0, 0, 0));
        b.emit(Insn::new(ATOMIC_ADD_DW, 6, 2, 24, 0xf1));
        let won = ahead(b, 0x1d, 0, 3, 0);
        b.jump(Insn::new(JNE_X, 0, 2, 0, 0), Label::Drop);
        self.source_identity(b, 6, Label::Drop);
        self.first_effect(b);
        b.emit(Insn::new(LDX_DW, 1, 10, ROOT_POINTER, 0));
        same64(b, 1, 0, 10, OPEN_EPOCH, Label::Drop);
        patch(b, won);
        b.emit(Insn::new(CALL, 0, 0, 0, 5));
        b.emit(Insn::new(STX_DW, 6, 0, 32, 0));
        patch(b, active);
    }

    fn first_effect(&self, b: &mut Builder) {
        same64(b, 6, 0, 10, OPEN_EPOCH, Label::Drop);
        for (from, to) in [(64, MARK_KIND), (68, MARK_VALUE)] {
            b.emit(Insn::new(LDX_W, 0, 6, from, 0));
            b.emit(Insn::new(LDX_W, 1, 10, to, 0));
            b.jump(Insn::new(JNE_X, 0, 1, 0, 0), Label::Drop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn action_identity_keeps_explicit_zero_and_full_marks() {
        validate_actions(&[None, Some(0), Some(0x8000_0000), Some(u32::MAX)]).unwrap();
        assert!(validate_actions(&[None, None]).is_err());
        assert!(validate_actions(&[Some(1), Some(0)]).is_err());
        assert!(validate_actions(&[]).is_err());
        assert_eq!(size_of::<NativeKey>(), 56);
        assert_eq!(size_of::<NativeClaim>(), 72);
    }

    #[test]
    fn emitted_source_and_matchers_keep_locks_and_effects_separate() {
        let source = HostSourceConfig {
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
        let owner = HostNativeConfig {
            source,
            family: libc::AF_INET as u8,
            scope: 9,
            layout: HostNativeLayout {
                cast: 1,
                hooks_entries: 8,
                hook_stride: 16,
                hook_private: 8,
                producer_callback: 1,
                ..Default::default()
            },
        };
        let mut bytecode = [bpf_insn {
            code: 0,
            _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
            off: 0,
            imm: 0,
        }; 2];
        bytecode[0].code = MOV_K;
        bytecode[1].code = EXIT;
        let policy = NativeProgramConfig {
            bytecode: &bytecode,
            root: 20,
            claims: 21,
            scratch: 22,
            closed_counters: 23,
            hook_ids: [1, 2],
            epoch: 2,
            scope: 9,
            expires_boottime_ns: 100,
            redirect_limit: 1,
            captured: None,
            reply_block_rules: &[],
            preparation_memory_bytes: 0,
        };
        let maps = RawMaps {
            root: 20,
            claims: 21,
            scratch: 22,
            source: Maps {
                facts: -1,
                gate: 10,
                sequence: 11,
                sockets: 12,
                socket_locks: 13,
                returns: 14,
            },
        };
        let selection = Selection {
            owner: &owner,
            maps,
            policy: Some(&policy),
            producer_id: 40,
        };
        let source = selector_with(&owner.source, maps.source, 0, Some(&selection)).unwrap();
        assert_unlocked_helpers(&source);
        let keep = selection.matcher(Some(None)).unwrap();
        let set_zero = selection.matcher(Some(Some(0))).unwrap();
        for program in [
            keep,
            set_zero,
            selection.matcher(Some(Some(u32::MAX))).unwrap(),
            selection.matcher(None).unwrap(),
        ] {
            assert_unlocked_helpers(&program);
            assert!(
                !program
                    .insns
                    .iter()
                    .any(|i| i.code == CALL && i.regs >> 4 == 0 && matches!(i.imm, 93 | 94))
            );
            assert!(
                !program
                    .insns
                    .iter()
                    .any(|i| i.code == LD_MAP && i.regs >> 4 == 1 && i.imm == 13)
            );
        }
        assert_unlocked_helpers(&selection.binding().unwrap());
        let mut oversized_bytecode = bytecode;
        oversized_bytecode[0]._bitfield_1 = bpf_insn::new_bitfield_1(0, 10);
        oversized_bytecode[0].code = MOV_X;
        let oversized = NativeProgramConfig {
            bytecode: &oversized_bytecode,
            ..policy
        };
        let oversized = Selection {
            policy: Some(&oversized),
            ..selection
        };
        assert!(oversized.matcher(Some(None)).is_err());
    }

    const ROOT: usize = 0x1000;
    const WORK: usize = 0x1100;
    const BANK: usize = 0x3000;
    const GATE: usize = 0x3500;
    const SEQUENCE: usize = 0x3510;
    const RETURN: usize = 0x3540;
    const CONTEXT: usize = 0x3600;
    const STATE: usize = 0x3650;
    const SKB: usize = 0x3700;
    const SOCKET: usize = 0x3800;
    const NETNS: usize = 0x3900;
    const DEV: usize = 0x3a00;
    const DST: usize = 0x3b00;
    const HOOKS: usize = 0x3c00;
    const PROG: usize = 0x3d00;
    const AUX: usize = 0x3e00;
    const PACKET: usize = 0x4000;
    const CT: usize = 0x4100;
    const STACK: usize = 0x10000;
    const MAPS: RawMaps = RawMaps {
        root: 20,
        claims: 21,
        scratch: 22,
        source: Maps {
            facts: -1,
            gate: 10,
            sequence: 11,
            sockets: 12,
            socket_locks: 13,
            returns: 14,
        },
    };

    fn put(memory: &mut [u8], at: usize, value: u64, bytes: usize) {
        memory[at..at + bytes].copy_from_slice(&value.to_ne_bytes()[..bytes]);
    }

    fn get(memory: &[u8], at: usize, bytes: usize) -> u64 {
        let mut value = [0; 8];
        value[..bytes].copy_from_slice(&memory[at..at + bytes]);
        u64::from_ne_bytes(value)
    }

    struct HostRun {
        owner: HostNativeConfig,
        memory: Vec<u8>,
        aliases: Vec<([u8; 56], usize)>,
        next_alias: usize,
        output: KernelRouteOutput,
        canonical: Vec<(u32, u32)>,
        now: u64,
        boot: u64,
        expiry: u64,
        updates: usize,
        fail_update: Option<usize>,
        collide_on_update: Option<usize>,
        fail_delete: bool,
        close_after_update: Option<usize>,
        replace_on_failure: bool,
        final_epoch: Option<u64>,
        final_now: Option<u64>,
    }

    impl HostRun {
        fn new(family: u8, protocol: u8, selection: u32) -> Self {
            let owner = HostNativeConfig {
                source: HostSourceConfig {
                    source_netns: 1,
                    attachment: 2,
                    private_tx: 3,
                    bypass_mark: 0x100,
                    tx_mac: [2; 6],
                    rx_mac: [4; 6],
                    skb_sk_offset: 0,
                    sock_net_pointer_offset: 24,
                    net_cookie_offset: 0,
                    skb_destructor_offset: 8,
                    skb_truesize_offset: 16,
                    sock_wmem_offset: 32,
                    sock_refcnt_offset: 36,
                    sock_write_queue_len_offset: 40,
                    sock_wfree: 99,
                },
                family,
                scope: 9,
                layout: HostNativeLayout {
                    cast: 1,
                    sock_cookie: 0,
                    sock_family: 8,
                    sock_state: 10,
                    sock_type: 12,
                    sock_protocol: 14,
                    sock_mark: 16,
                    skb_len: 24,
                    skb_data_len: 28,
                    skb_data: 32,
                    skb_protocol: 40,
                    skb_mark: 44,
                    skb_refdst: 48,
                    skb_nfct: 56,
                    dst_dev: 0,
                    dev_ifindex: 0,
                    dev_net: 8,
                    state_net: 0,
                    state_out: 8,
                    state_hook: 16,
                    state_pf: 17,
                    ct_net: 0,
                    ct_status: 8,
                    ct_zone_id: 16,
                    ct_zone_dir: 18,
                    ct_zone_flags: 19,
                    ct_src: 24,
                    ct_dst: 40,
                    ct_sport: 56,
                    ct_dport: 58,
                    ct_family: 60,
                    ct_protocol: 62,
                    net_hooks_ipv4: 8,
                    net_hooks_ipv6: 48,
                    hooks_count: 0,
                    hooks_entries: 8,
                    hook_stride: 16,
                    hook_callback: 0,
                    hook_private: 8,
                    prog_aux: 0,
                    aux_id: 0,
                    producer_callback: 77,
                },
            };
            let mut memory = vec![0; STACK + 512];
            let v4 = family == libc::AF_INET as u8;
            let header = if v4 { 20 } else { 40 };
            let upper = if protocol == 6 { 20 } else { 8 };
            for (at, value, bytes) in [
                (ROOT, 3, 8),
                (ROOT + 8, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as u64, 4),
                (GATE, 1, 4),
                (SEQUENCE + 8, 100, 8),
                (RETURN, 1, 8),
                (RETURN + 8, 5, 4),
                (CONTEXT, STATE as u64, 8),
                (CONTEXT + 8, SKB as u64, 8),
                (STATE, NETNS as u64, 8),
                (STATE + 8, DEV as u64, 8),
                (STATE + 16, 3, 1),
                (STATE + 17, family as u64, 1),
                (SKB, SOCKET as u64, 8),
                (SKB + 8, 99, 8),
                (SKB + 16, 100, 4),
                (SKB + 24, (header + upper) as u64, 4),
                (SKB + 32, PACKET as u64, 8),
                (
                    SKB + 40,
                    (if v4 { 0x0800u16 } else { 0x86dd }).to_be() as u64,
                    2,
                ),
                (SKB + 48, DST as u64, 8),
                (SKB + 56, CT as u64, 8),
                (SOCKET, 7, 8),
                (SOCKET + 8, family as u64, 2),
                (SOCKET + 10, 1, 1),
                (SOCKET + 12, if protocol == 6 { 1 } else { 2 }, 2),
                (SOCKET + 14, protocol as u64, 2),
                (SOCKET + 24, NETNS as u64, 8),
                (SOCKET + 32, 101, 4),
                (SOCKET + 36, 1, 4),
                (NETNS, 1, 8),
                (NETNS + 32, HOOKS as u64, 8),
                (NETNS + 72, HOOKS as u64, 8),
                (DEV, 5, 4),
                (DEV + 8, NETNS as u64, 8),
                (DST, DEV as u64, 8),
                (HOOKS, 1, 2),
                (HOOKS + 8, 77, 8),
                (HOOKS + 16, PROG as u64, 8),
                (PROG, AUX as u64, 8),
                (AUX, 40, 4),
                (BANK + 8, 7, 8),
                (BANK + 16, SOCKET as u64, 8),
                (BANK + 48, 33, 8),
                (BANK + 60, selection as u64, 4),
                (CT, NETNS as u64, 8),
                (CT + 16, 7, 2),
                (CT + 18, 3, 1),
                (CT + 60, family as u64, 2),
                (CT + 62, protocol as u64, 1),
            ] {
                put(&mut memory, at, value, bytes);
            }
            if v4 {
                memory[PACKET] = 0x45;
                memory[PACKET + 2..PACKET + 4]
                    .copy_from_slice(&((header + upper) as u16).to_be_bytes());
                memory[PACKET + 9] = protocol;
                memory[PACKET + 12..PACKET + 16].copy_from_slice(&[10, 0, 0, 1]);
                memory[PACKET + 16..PACKET + 20].copy_from_slice(&[1, 1, 1, 1]);
            } else {
                memory[PACKET] = 0x60;
                memory[PACKET + 4..PACKET + 6].copy_from_slice(&(upper as u16).to_be_bytes());
                memory[PACKET + 6] = protocol;
                memory[PACKET + 8] = 0xfd;
                memory[PACKET + 23] = 1;
                memory[PACKET + 24] = 0xfd;
                memory[PACKET + 39] = 2;
            }
            memory[PACKET + header..PACKET + header + 2].copy_from_slice(&12345u16.to_be_bytes());
            memory[PACKET + header + 2..PACKET + header + 4].copy_from_slice(&443u16.to_be_bytes());
            if protocol == 6 {
                memory[PACKET + header + 12] = 0x50;
                memory[PACKET + header + 13] = 2;
            } else {
                memory[PACKET + header + 4..PACKET + header + 6]
                    .copy_from_slice(&8u16.to_be_bytes());
            }
            if v4 {
                memory.copy_within(PACKET + 12..PACKET + 16, CT + 24);
                memory.copy_within(PACKET + 16..PACKET + 20, CT + 40);
            } else {
                memory.copy_within(PACKET + 8..PACKET + 40, CT + 24);
            }
            memory.copy_within(PACKET + header..PACKET + header + 4, CT + 56);
            Self {
                owner,
                memory,
                aliases: Vec::new(),
                next_alias: 0x5000,
                output: KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 0,
                        domain_final: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                canonical: Vec::new(),
                now: 1_000_000_000,
                boot: 10,
                expiry: 1000,
                updates: 0,
                fail_update: None,
                fail_delete: false,
                close_after_update: None,
                collide_on_update: None,
                replace_on_failure: false,
                final_epoch: None,
                final_now: None,
            }
        }

        fn key(&self, domain: u8) -> [u8; 56] {
            let mut key = [0; 56];
            let v4 = self.owner.family == libc::AF_INET as u8;
            if v4 {
                key[10..12].fill(255);
                key[26..28].fill(255);
                key[12..16].copy_from_slice(&self.memory[PACKET + 12..PACKET + 16]);
                key[28..32].copy_from_slice(&self.memory[PACKET + 16..PACKET + 20]);
            } else {
                key[..32].copy_from_slice(&self.memory[PACKET + 8..PACKET + 40]);
            }
            let ports = PACKET + if v4 { 20 } else { 40 };
            key[32..36].copy_from_slice(&self.memory[ports..ports + 4]);
            key[36] = self.memory[SOCKET + 14];
            key[37] = if v4 { 4 } else { 6 };
            key[38] = domain;
            key[40..48].copy_from_slice(&1u64.to_ne_bytes());
            key
        }

        fn active(&mut self, mark: Option<u32>, last_seen: u64) -> usize {
            let at = self.next_alias;
            self.next_alias += 128;
            self.aliases.push((self.key(NATIVE_DOMAIN_SOURCE), at));
            for (offset, value, bytes) in [
                (0, 3, 8),
                (8, 3, 8),
                (16, 9, 8),
                (24, NATIVE_EXECUTOR_KERNEL as u64, 4),
                (28, NATIVE_PHASE_ACTIVE as u64, 4),
                (32, last_seen, 8),
                (40, 7, 8),
                (48, 33, 8),
                (56, 2, 8),
                (64, u64::from(mark.is_some()), 4),
                (68, u64::from(mark.unwrap_or(0)), 4),
            ] {
                put(&mut self.memory, at + offset, value, bytes);
            }
            at
        }

        fn run(&mut self, matcher: bool, mark: Option<u32>) -> u64 {
            let bytecode = [
                bpf_insn {
                    code: MOV_K,
                    _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                    off: 0,
                    imm: 0,
                },
                bpf_insn {
                    code: EXIT,
                    _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                    off: 0,
                    imm: 0,
                },
            ];
            let policy = NativeProgramConfig {
                bytecode: &bytecode,
                root: 20,
                claims: 21,
                scratch: 22,
                closed_counters: 23,
                hook_ids: [1, 2],
                epoch: 2,
                scope: 9,
                expires_boottime_ns: self.expiry,
                redirect_limit: 1,
                captured: None,
                reply_block_rules: &[],
                preparation_memory_bytes: 0,
            };
            let selection = Selection {
                owner: &self.owner,
                maps: MAPS,
                policy: Some(&policy),
                producer_id: 40,
            };
            let program = if matcher {
                selection.matcher(Some(mark)).unwrap()
            } else {
                selector_with(
                    &self.owner.source,
                    selection.maps.source,
                    0,
                    Some(&selection),
                )
                .unwrap()
            };
            self.execute(&program)
        }

        fn bind(&mut self) -> u64 {
            let program = Selection {
                owner: &self.owner,
                maps: MAPS,
                policy: None,
                producer_id: 40,
            }
            .binding()
            .unwrap();
            self.execute(&program)
        }

        fn execute(&mut self, program: &Program) -> u64 {
            let mut memory = std::mem::take(&mut self.memory);
            let mut regs = [0; 11];
            regs[1] = CONTEXT as u64;
            regs[10] = STACK as u64;
            self.canonical.clear();
            self.updates = 0;
            let mut locked = false;
            let result = crate::bpf::native::tests::execute(
                program,
                &mut memory,
                &mut regs,
                |insn, regs, memory| {
                    if insn.code == ATOMIC_ADD_DW
                        && insn.imm == 0xf1
                        && regs[(insn.regs & 15) as usize] == ROOT as u64
                        && let Some(epoch) = self.final_epoch
                    {
                        put(memory, ROOT, epoch, 8);
                    }
                    if insn.code != CALL {
                        return false;
                    }
                    if insn.code == CALL
                        && insn.imm == 125
                        && let Some(now) = self.final_now
                    {
                        self.now = now;
                    }
                    let helper = (insn.regs >> 4, insn.imm);
                    if helper == (0, 94) {
                        assert!(locked);
                        locked = false;
                    } else {
                        assert!(!locked, "helper under bank lock");
                    }
                    regs[0] = match helper {
                        (1, _) => {
                            let input = regs[1] as usize;
                            self.canonical.push((
                                get(
                                    memory,
                                    input + std::mem::offset_of!(RoutingInput, l4proto),
                                    4,
                                ) as u32,
                                get(
                                    memory,
                                    input + std::mem::offset_of!(RoutingInput, ip_version),
                                    4,
                                ) as u32,
                            ));
                            for (offset, value) in [
                                (
                                    std::mem::offset_of!(RoutingDecision, outbound),
                                    self.output.decision.outbound,
                                ),
                                (
                                    std::mem::offset_of!(RoutingDecision, mark),
                                    self.output.decision.mark,
                                ),
                                (
                                    std::mem::offset_of!(RoutingDecision, must),
                                    self.output.decision.must,
                                ),
                                (
                                    std::mem::offset_of!(RoutingDecision, domain_final),
                                    self.output.decision.domain_final,
                                ),
                                (
                                    std::mem::offset_of!(KernelRouteOutput, mark_kind),
                                    self.output.mark_kind,
                                ),
                            ] {
                                put(memory, regs[2] as usize + offset, u64::from(value), 4);
                            }
                            0
                        }
                        (2, 1) => SKB as u64,
                        (0, 113) => {
                            memory.copy_within(
                                regs[3] as usize..(regs[3] + regs[2]) as usize,
                                regs[1] as usize,
                            );
                            0
                        }
                        (0, 8) => 0,
                        (0, 5) => self.now,
                        (0, 125) => self.boot,
                        (0, 93) => {
                            locked = true;
                            0
                        }
                        (0, 94) => 0,
                        (0, 1) => match regs[1] {
                            10 => GATE as u64,
                            11 => SEQUENCE as u64,
                            12 => BANK as u64,
                            13 => 0x3400,
                            14 => RETURN as u64,
                            20 => ROOT as u64,
                            22 => WORK as u64,
                            21 => self
                                .aliases
                                .iter()
                                .find(|(key, _)| {
                                    key[..] == memory[regs[2] as usize..regs[2] as usize + 56]
                                })
                                .map_or(0, |(_, at)| *at as u64),
                            fd => panic!("unexpected Host map {fd}"),
                        },
                        (0, 2) => {
                            self.updates += 1;
                            assert_eq!(regs[4], 1);
                            let key: [u8; 56] = memory[regs[2] as usize..regs[2] as usize + 56]
                                .try_into()
                                .unwrap();
                            if self.fail_update == Some(self.updates) {
                                if self.replace_on_failure {
                                    put(memory, BANK + 48, 999, 8);
                                    put(memory, BANK + 60, HOST_SOCKET_NATIVE as u64, 4);
                                }
                                -libc::ENOSPC as i64 as u64
                            } else if self.collide_on_update == Some(self.updates) {
                                let at = self.next_alias;
                                self.next_alias += 128;
                                memory.copy_within(regs[3] as usize..regs[3] as usize + 72, at);
                                put(memory, at + 48, 999, 8);
                                self.aliases.push((key, at));
                                -libc::EEXIST as i64 as u64
                            } else if self.aliases.iter().any(|(old, _)| *old == key) {
                                -libc::EEXIST as i64 as u64
                            } else {
                                let at = self.next_alias;
                                self.next_alias += 128;
                                memory.copy_within(regs[3] as usize..regs[3] as usize + 72, at);
                                self.aliases.push((key, at));
                                if self.close_after_update == Some(self.updates) {
                                    put(memory, GATE, 0, 4);
                                }
                                0
                            }
                        }
                        (0, 3) => {
                            if self.fail_delete {
                                -libc::EIO as i64 as u64
                            } else if let Some(index) = self.aliases.iter().position(|(key, _)| {
                                key[..] == memory[regs[2] as usize..regs[2] as usize + 56]
                            }) {
                                self.aliases.remove(index);
                                0
                            } else {
                                -libc::ENOENT as i64 as u64
                            }
                        }
                        other => panic!("unexpected Host helper {other:?}"),
                    };
                    regs[1..6].fill(0xdead);
                    true
                },
            );
            assert!(!locked);
            assert_eq!(get(&memory, WORK + S_BUSY as usize, 4), 0);
            self.memory = memory;
            result
        }
    }

    #[test]
    fn host_consumers_normalize_wire_input_and_accept_later_open_epochs() {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            for protocol in [6, 17] {
                let mut run = HostRun::new(
                    family,
                    protocol,
                    if protocol == 6 {
                        HOST_SOCKET_CANDIDATE
                    } else {
                        HOST_SOCKET_BORN_NEW
                    },
                );
                put(&mut run.memory, ROOT, 9, 8);
                assert_eq!(run.run(false, None), 1);
                let expected = (
                    if protocol == 6 { 1 } else { 2 },
                    if family == libc::AF_INET as u8 { 1 } else { 2 },
                );
                assert_eq!(run.canonical, [expected]);
                assert_eq!(run.run(true, None), 1);
                assert_eq!(run.canonical, [expected]);
                run.final_epoch = Some(10);
                assert_eq!(run.run(true, None), 0);
            }
        }
    }

    #[test]
    fn active_tcp_keeps_frozen_effect_through_reload_but_obeys_withdrawal() {
        for mark in [None, Some(0), Some(u32::MAX)] {
            let mut run = HostRun::new(libc::AF_INET as u8, 6, HOST_SOCKET_NATIVE);
            run.active(mark, run.now);
            run.output.decision.outbound = 1;
            put(&mut run.memory, ROOT, 9, 8);
            assert_eq!(run.run(false, mark), 1);
            assert!(run.canonical.is_empty());
            assert_eq!(run.run(true, mark), 1);
            assert!(run.canonical.is_empty());
            assert_eq!(run.run(true, Some(7)), 0);
            put(&mut run.memory, GATE, 0, 4);
            assert_eq!(run.run(true, mark), 0);
            put(&mut run.memory, GATE, 1, 4);
            run.boot = run.expiry;
            assert_eq!(run.run(true, mark), 0);
        }
    }

    #[test]
    fn udp_retained_effect_refuses_strictly_expired_hits_without_refresh() {
        let timeout = honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;
        for elapsed in [timeout, timeout + 1] {
            for matcher in [false, true] {
                let mut run = HostRun::new(libc::AF_INET6 as u8, 17, HOST_SOCKET_NATIVE);
                let at = run.active(Some(0), run.now);
                let before = run.now;
                run.now += elapsed;
                run.output.decision.outbound = 1;
                assert_eq!(run.run(matcher, Some(0)), u64::from(elapsed == timeout));
                assert!(run.canonical.is_empty());
                assert_eq!(
                    get(&run.memory, at + 32, 8),
                    if matcher && elapsed == timeout {
                        run.now
                    } else {
                        before
                    }
                );
            }
        }
    }

    #[test]
    fn first_admission_and_udp_dns_do_not_borrow_active_continuations() {
        let mut run = HostRun::new(libc::AF_INET as u8, 6, HOST_SOCKET_CANDIDATE);
        run.memory[PACKET + 20 + 13] = 0x10;
        assert_eq!(run.run(false, None), 0);
        assert!(run.aliases.is_empty());
        assert_eq!(
            get(&run.memory, BANK + 60, 4),
            u64::from(HOST_SOCKET_CANDIDATE)
        );
        let mut run = HostRun::new(libc::AF_INET as u8, 6, HOST_SOCKET_CANDIDATE);
        assert_eq!(run.run(false, None), 1);
        run.output.decision.outbound = 1;
        assert_eq!(run.run(true, None), 0);
        assert_eq!(run.canonical.len(), 1);
        let mut run = HostRun::new(libc::AF_INET as u8, 17, HOST_SOCKET_NATIVE);
        run.memory[PACKET + 22..PACKET + 24].copy_from_slice(&53u16.to_be_bytes());
        run.active(Some(0), run.now);
        run.output.decision.outbound = 1;
        assert_eq!(run.run(false, Some(0)), 0);
        assert_eq!(run.canonical.len(), 1);
        assert_eq!(run.run(true, Some(0)), 0);
        assert_eq!(run.canonical.len(), 1);
    }

    #[test]
    fn udp_expiring_at_final_frontier_is_not_refreshed() {
        let mut run = HostRun::new(libc::AF_INET as u8, 17, HOST_SOCKET_NATIVE);
        let last_seen = run.now;
        let at = run.active(None, last_seen);
        run.now += honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS;
        run.final_now = Some(run.now + 1);
        assert_eq!(run.run(true, None), 0);
        assert_eq!(get(&run.memory, at + 32, 8), last_seen);
    }

    #[test]
    fn alias_failures_restore_only_exact_uncommitted_source() {
        for protocol in [6, 17] {
            let prior = if protocol == 6 {
                HOST_SOCKET_CANDIDATE
            } else {
                HOST_SOCKET_BORN_NEW
            };
            for failure in [1, 2] {
                let mut run = HostRun::new(libc::AF_INET as u8, protocol, prior);
                run.fail_update = Some(failure);
                assert_eq!(run.run(false, None), 0);
                assert!(run.aliases.is_empty());
                assert_eq!(get(&run.memory, BANK + 60, 4), u64::from(prior));
                assert_eq!(get(&run.memory, BANK + 48, 8), 33);
                run.fail_update = None;
                assert_eq!(run.run(false, None), 1);
            }
            let mut run = HostRun::new(libc::AF_INET as u8, protocol, prior);
            run.close_after_update = Some(2);
            assert_eq!(run.run(false, None), 0);
            assert!(run.aliases.is_empty());
            assert_eq!(get(&run.memory, BANK + 60, 4), u64::from(prior));
            let mut run = HostRun::new(libc::AF_INET as u8, protocol, prior);
            run.fail_update = Some(2);
            run.fail_delete = true;
            assert_eq!(run.run(false, None), 0);
            assert_eq!(run.aliases.len(), 1);
            assert_eq!(
                get(&run.memory, BANK + 60, 4),
                u64::from(HOST_SOCKET_TRANSITION)
            );
            let mut run = HostRun::new(libc::AF_INET as u8, protocol, prior);
            run.fail_update = Some(2);
            run.replace_on_failure = true;
            assert_eq!(run.run(false, None), 0);
            assert_eq!(run.aliases.len(), 1);
            assert_eq!(get(&run.memory, BANK + 48, 8), 999);
            assert_eq!(
                get(&run.memory, BANK + 60, 4),
                u64::from(HOST_SOCKET_NATIVE)
            );
            let mut run = HostRun::new(libc::AF_INET as u8, protocol, prior);
            run.collide_on_update = Some(2);
            assert_eq!(run.run(false, None), 0);
            assert_eq!(run.aliases.len(), 1);
            let (key, at) = run.aliases[0];
            assert_eq!(key[38], NATIVE_DOMAIN_SOURCE);
            assert_eq!(get(&run.memory, at + 48, 8), 999);
            assert_eq!(get(&run.memory, BANK + 60, 4), u64::from(prior));
        }
    }

    #[test]
    fn failed_frozen_source_only_returns_its_own_pending_reservation() {
        let mut run = HostRun::new(libc::AF_INET as u8, 6, HOST_SOCKET_NATIVE);
        let source = run.active(Some(u32::MAX), run.now);
        let pending = run.next_alias;
        run.next_alias += 128;
        run.memory.copy_within(source..source + 72, pending);
        put(
            &mut run.memory,
            pending + 24,
            NATIVE_EXECUTOR_PENDING as u64,
            4,
        );
        put(
            &mut run.memory,
            pending + 28,
            (NATIVE_PHASE_SOURCE_PENDING | (1 << 4)) as u64,
            4,
        );
        put(&mut run.memory, pending + 64, 0, 8);
        run.aliases
            .push((run.key(NATIVE_DOMAIN_UNBOUND_SOURCE), pending));
        run.fail_update = Some(2);
        assert_eq!(run.run(false, Some(u32::MAX)), 0);
        assert_eq!(run.aliases.len(), 2);
        assert_eq!(
            get(&run.memory, pending + 28, 4),
            u64::from(NATIVE_PHASE_SOURCE_PENDING | (1 << 4))
        );
        assert_eq!(
            get(&run.memory, source + 28, 4),
            u64::from(NATIVE_PHASE_ACTIVE)
        );
        assert_eq!(get(&run.memory, source + 68, 4), u64::from(u32::MAX));
        assert_eq!(
            get(&run.memory, BANK + 60, 4),
            u64::from(HOST_SOCKET_NATIVE)
        );
    }

    #[test]
    fn failed_selection_does_not_claim_ownership_of_existing_source_alias() {
        let mut run = HostRun::new(libc::AF_INET as u8, 6, HOST_SOCKET_CANDIDATE);
        let source = run.active(None, run.now);
        put(&mut run.memory, source + 28, NATIVE_PHASE_ARMED as u64, 4);
        run.close_after_update = Some(1);
        assert_eq!(run.run(false, None), 0);
        assert_eq!(run.aliases.len(), 2);
        assert_eq!(
            get(&run.memory, BANK + 60, 4),
            u64::from(HOST_SOCKET_TRANSITION)
        );
        assert_eq!(
            get(&run.memory, source + 28, 4),
            u64::from(NATIVE_PHASE_ARMED)
        );
    }

    #[test]
    fn expired_udp_source_reenters_current_policy_without_replacing_socket_or_aliases() {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let a = 0x8000_0001;
            let b = 0;
            let mut run = HostRun::new(family, 17, HOST_SOCKET_BORN_NEW);
            run.output.mark_kind = ROUTING_MARK_SET;
            run.output.decision.mark = a;
            assert_eq!(run.run(false, Some(a)), 1);
            assert_eq!(run.run(true, Some(a)), 1);
            assert_eq!(run.bind(), 1);
            let source_key = run.key(NATIVE_DOMAIN_SOURCE);
            let source = run
                .aliases
                .iter()
                .find(|(key, _)| *key == source_key)
                .unwrap()
                .1;
            let bank = run.memory[BANK..BANK + 520].to_vec();
            let bound: Vec<_> = run
                .aliases
                .iter()
                .filter(|(key, _)| key[38] == NATIVE_DOMAIN_FLOW)
                .map(|(key, at)| {
                    assert_eq!(key[50], NATIVE_ZONE_BOUND_ACTUAL);
                    assert_eq!(get(&run.memory, *at + 68, 4), u64::from(a));
                    (*key, *at)
                })
                .collect();
            assert_eq!(bound.len(), 2);
            assert_eq!(
                bound.iter().map(|(key, _)| key[39]).collect::<Vec<_>>(),
                [0, 1]
            );
            let pending = run.next_alias;
            run.next_alias += 128;
            run.memory.copy_within(source..source + 72, pending);
            put(
                &mut run.memory,
                pending + 24,
                NATIVE_EXECUTOR_PENDING as u64,
                4,
            );
            put(
                &mut run.memory,
                pending + 28,
                (NATIVE_PHASE_SOURCE_PENDING | (1 << 4)) as u64,
                4,
            );
            put(&mut run.memory, pending + 64, 0, 8);
            run.aliases
                .push((run.key(NATIVE_DOMAIN_UNBOUND_SOURCE), pending));
            let other = run.next_alias;
            run.next_alias += 128;
            run.memory.copy_within(source..source + 72, other);
            let mut other_key = source_key;
            other_key[34..36].copy_from_slice(&444u16.to_be_bytes());
            run.aliases.push((other_key, other));
            let retained: Vec<_> = run
                .aliases
                .iter()
                .filter(|(key, _)| *key != source_key)
                .map(|(key, at)| (*key, *at, run.memory[*at..*at + 72].to_vec()))
                .collect();

            put(&mut run.memory, ROOT, 9, 8);
            run.output.decision.mark = b;
            run.now += honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS + 1;
            assert_eq!(run.run(false, Some(a)), 0);
            assert!(run.canonical.is_empty());
            assert_eq!(run.run(true, Some(a)), 0);
            assert!(run.canonical.is_empty());
            // Model only the exact Source deletion, not execution of the Core retirement owner.
            put(&mut run.memory, ROOT, 10, 8);
            let index = run
                .aliases
                .iter()
                .position(|(key, at)| *key == source_key && *at == source)
                .unwrap();
            run.aliases.remove(index);
            put(&mut run.memory, ROOT, 11, 8);
            assert_eq!(run.run(false, Some(b)), 1);
            assert_eq!(run.canonical.len(), 1);
            assert_eq!(run.run(true, Some(b)), 1);
            assert_eq!(run.canonical.len(), 1);
            assert_eq!(run.bind(), 1);
            let replacement = run
                .aliases
                .iter()
                .find(|(key, _)| *key == source_key)
                .unwrap()
                .1;
            assert_ne!(replacement, source);
            assert_eq!(
                get(&run.memory, replacement + 28, 4),
                u64::from(NATIVE_PHASE_ACTIVE)
            );
            assert_eq!(
                get(&run.memory, replacement + 64, 4),
                u64::from(ROUTING_MARK_SET)
            );
            assert_eq!(get(&run.memory, replacement + 68, 4), u64::from(b));
            assert_eq!(get(&run.memory, replacement + 32, 8), run.now);
            assert_eq!(&run.memory[BANK..BANK + 520], bank.as_slice());
            assert_eq!(run.aliases.len(), retained.len() + 1);
            for (key, at, bytes) in retained {
                assert!(run.aliases.contains(&(key, at)));
                assert_eq!(&run.memory[at..at + 72], bytes.as_slice());
            }
        }
    }

    fn assert_unlocked_helpers(program: &Program) {
        let mut seen = vec![[false; 2]; program.len];
        let mut pending = vec![(0usize, false)];
        while let Some((pc, mut locked)) = pending.pop() {
            assert!(pc < program.len);
            if seen[pc][usize::from(locked)] {
                continue;
            }
            seen[pc][usize::from(locked)] = true;
            let i = program.insns[pc];
            if i.code == CALL {
                match (i.regs >> 4, i.imm) {
                    (0, 93) => {
                        assert!(!locked);
                        locked = true;
                    }
                    (0, 94) => {
                        assert!(locked);
                        locked = false;
                    }
                    _ => assert!(!locked, "helper/canonical body under bank lock at {pc}"),
                }
            }
            if i.code == EXIT {
                assert!(!locked);
                continue;
            }
            if matches!(i.code & 7, 5 | 6) && i.code != CALL {
                pending.push(((pc as isize + 1 + i.off as isize) as usize, locked));
                if i.code == JA {
                    continue;
                }
            }
            pending.push((pc + if i.code == LD_MAP { 2 } else { 1 }, locked));
        }
    }
}
