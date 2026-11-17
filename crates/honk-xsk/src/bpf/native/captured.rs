use super::*;
use honk_ebpf_common::xdp::{
    NATIVE_OP_ADMITTED, NATIVE_OP_ADMITTING, NATIVE_OP_ENTERED, NATIVE_OP_ENTERING,
    NATIVE_OP_GATE_REFUSED, NATIVE_OP_PREPARED, NATIVE_OP_REDIRECT_REQUESTED,
    NATIVE_OP_REDIRECTING, NativeCapturedOperation,
};
use std::ffi::{CStr, CString};

const STATIC_LIMIT: usize = 4096;
// The entry observer must fit the plan's fixed static instruction budget before TAP creation.
const MAX_CAPTURED_TARGETS: usize = (STATIC_LIMIT - 256) / 8;
const PHASE: i16 = 192;
const OP_KEY: i16 = 112;
const SAVED_CB: i16 = 216;
const RECEIPT: i16 = 236;
const ENTRY_SEQ: i16 = 240;
const OP_PTR: i16 = CLAIM;
const STATIC_ROLES: [&str; 6] = [
    "tap-xdp-guard",
    "tap-xdp-dispatch",
    "tap-tcx-redirect-prog",
    "tap-tcx-guard-prog",
    "native-return-restorer-prog",
    "target-entry-prog",
];
const STATIC_NAMES: [&[u8]; 6] = [
    b"honk_ret_guard",
    b"honk_ret_xdp",
    b"honk_ret_redir",
    b"honk_ret_tcgrd",
    b"honk_ret_rstor",
    b"honk_ret_entry",
];
// BPF_OBJ_NAME_LEN is 16 including NUL; object_name() would otherwise panic at load time.
const _: () = {
    let mut index = 0;
    while index < STATIC_NAMES.len() {
        assert!(STATIC_NAMES[index].len() < 16);
        index += 1;
    }
};

#[derive(Clone)]
pub struct CapturedTarget {
    pub realm_index: u32,
    pub logical_ifindex: u32,
    pub target: Arc<NativeTarget>,
}

pub struct CapturedProgramConfig<'a> {
    pub root: BorrowedFd<'a>,
    pub operation: BorrowedFd<'a>,
    pub return_attachment: u64,
    pub tap_ifindex: u32,
    pub targets: &'a [CapturedTarget],
    pub pin_root: &'a Path,
}

pub struct CapturedLayout {
    kernel: layout::CapturedLayout,
    authority: honk_ebpf_common::xdp::CaptureAuthority,
    module_guard: std::fs::File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturedResourceState {
    Installed,
    Detached,
    Unpinned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedResource {
    pub role: &'static str,
    pub pin_path: PathBuf,
    pub kind: u32,
    pub id: u32,
    pub ifindex: u32,
    pub state: CapturedResourceState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedGateIdentity {
    pub resource: CapturedResource,
    pub realm_index: u32,
    pub closed_epoch: u64,
}

struct Object {
    receipt: CapturedResource,
    fd: Option<OwnedFd>,
    pinned: bool,
    installed: bool,
    intent: bool,
    memlock: usize,
}

struct RealmGate {
    realm: u32,
    object: usize,
    epoch: u64,
    selected: bool,
}

struct Installed {
    objects: Vec<Object>,
    directory_intent: bool,
    realms: Vec<RealmGate>,
    next_candidate: u64,
    sealed: bool,
    closed: bool,
    complete: bool,
}

struct CapturedState {
    root: OwnedFd,
    operation: OwnedFd,
    root_id: u32,
    operation_id: u32,
    directory: Mutex<Option<OwnedFd>>,
    path: PathBuf,
    pin_root: PathBuf,
    attachment: u64,
    tap: u32,
    namespace: u64,
    targets: Vec<CapturedTarget>,
    gates: Vec<Arc<NativeTcxAttachment>>,
    layout: layout::CapturedLayout,
    installed: Mutex<Installed>,
}

#[derive(Clone)]
pub struct CapturedPrograms(Arc<CapturedState>);

pub(in crate::bpf) struct CanonicalGate {
    pub(in crate::bpf) program: OwnedFd,
    receipt: CapturedResource,
    owner: CapturedPrograms,
    realm: u32,
    epoch: u64,
    id: u32,
    object: usize,
}

fn capacity(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, message)
}

fn object_id(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut info = ProgInfo::default();
    object_info(fd, &mut info)?;
    if info.id == 0 {
        return Err(invalid_data("captured object has zero ID"));
    }
    Ok(info.id)
}

fn admit_map(
    fd: BorrowedFd<'_>,
    kind: u32,
    value: usize,
    entries: u32,
    flags: u32,
) -> io::Result<u32> {
    let mut info = CounterMapInfo::default();
    object_info(fd, &mut info)?;
    if info.kind != kind
        || info.id == 0
        || info.key_size != 4
        || info.value_size as usize != value
        || info.entries != entries
        || info.flags != flags
    {
        return Err(invalid_data("captured map ABI or identity mismatch"));
    }
    Ok(info.id)
}

fn gate_owner(target: &NativeTarget) -> io::Result<Arc<NativeTcxAttachment>> {
    let native = target
        .attachment
        .native
        .as_ref()
        .ok_or_else(|| invalid_data("captured target has no Native attachment"))?
        .lock()
        .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
    native.require_resolved()?;
    native
        .gate
        .clone()
        .ok_or_else(|| invalid_data("captured target has no owned TCX gate"))
}

impl NativeTarget {
    pub fn captured_preparation_bytes(
        max_physical_mtu: u32,
        target_count: usize,
    ) -> io::Result<usize> {
        if !(68..=65535).contains(&max_physical_mtu)
            || target_count == 0
            || target_count > MAX_CAPTURED_TARGETS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid captured preparation geometry",
            ));
        }
        let (preparation, cold_bytes) = layout::captured_preparation_bounds()?;
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|n| n.is_power_of_two())
            .ok_or_else(|| invalid_data("invalid page size"))?;
        let frame = (max_physical_mtu as usize)
            .checked_add(22)
            .and_then(|n| n.checked_add(page - 1))
            .map(|n| n & !(page - 1))
            .ok_or_else(|| capacity("captured frame allocation overflow"))?;
        let objects = target_count
            .checked_mul(4 * page + size_of::<CapturedTarget>() + size_of::<Object>() * 4)
            .ok_or_else(|| capacity("captured target allocation overflow"))?;
        frame
            .checked_mul(2)
            .and_then(|n| n.checked_add(64 << 10))
            .and_then(|n| n.checked_add(cold_bytes))
            // The parser returns only scalar layout before the static loader starts.
            .and_then(|n| n.checked_add(preparation.max(6 * STATIC_LIMIT * 256)))
            .and_then(|n| n.checked_add(objects))
            .and_then(|n| n.checked_add(16 * page))
            .ok_or_else(|| capacity("captured preparation allocation overflow"))
    }

    pub fn admit_captured_layout(&self) -> io::Result<CapturedLayout> {
        check_target_xdp(self)?;
        let (scratch, cold) = layout::captured_preparation_bounds()?;
        let module_guard = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        let kernel = layout::CapturedLayout::read()?;
        if kernel.cold_bytes > cold || scratch == 0 {
            return Err(capacity(
                "captured layout exceeds funded construction ceiling",
            ));
        }
        Ok(CapturedLayout {
            kernel,
            authority: self.capture.authority,
            module_guard,
        })
    }

    pub fn load_captured_programs(
        &self,
        config: &CapturedProgramConfig<'_>,
        layout: CapturedLayout,
    ) -> io::Result<CapturedPrograms> {
        validate_targets(self, config)?;
        if layout.authority != self.capture.authority {
            return Err(invalid_data("captured layout belongs to another target"));
        }
        let CapturedLayout {
            kernel: layout,
            module_guard: _module_guard,
            ..
        } = layout;
        let root_id = admit_map(config.root, 2, size_of::<NativeRoot>(), 1, 1 << 10)?;
        let operation_id = admit_map(
            config.operation,
            2,
            size_of::<NativeCapturedOperation>(),
            1,
            1 << 10,
        )?;
        let root: NativeRoot = map_value(config.root, &0)?;
        if root.epoch & 1 != 0 || root.reserved != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "captured installation requires a closed root",
            ));
        }
        let mut gates = Vec::new();
        gates
            .try_reserve_exact(config.targets.len())
            .map_err(|_| capacity("captured gate receipt allocation"))?;
        for descriptor in config.targets {
            let gate = gate_owner(&descriptor.target)?;
            gate.check()?;
            let expected = config
                .pin_root
                .join(format!("xdp-{}/native-gate-prog", gate.ifindex));
            if gate.pin_path() != expected {
                return Err(invalid_data(
                    "captured target pin is outside its exact daemon BPF root",
                ));
            }
            if gates
                .iter()
                .all(|owner: &Arc<NativeTcxAttachment>| owner.ifindex != gate.ifindex)
            {
                gates.push(gate);
            }
        }
        // The explicit daemon BPF root also owns the sibling xdp-<ifindex> directories.
        let path = config
            .pin_root
            .join(format!("native-return-{}", config.return_attachment));
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(12 + gates.len() * 2 + config.targets.len() * 2)
            .map_err(|_| capacity("captured object receipt allocation"))?;
        let (role, fd, id) = ("operation-map", config.operation, operation_id);
        objects.push(Object {
            receipt: CapturedResource {
                role,
                pin_path: path.join(role),
                kind: 2,
                id,
                ifindex: config.tap_ifindex,
                state: CapturedResourceState::Installed,
            },
            fd: Some(fd.try_clone_to_owned()?),
            pinned: false,
            installed: false,
            intent: false,
            memlock: 0,
        });
        let mut realms = Vec::new();
        realms
            .try_reserve_exact(config.targets.len() * 2)
            .map_err(|_| capacity("captured realm receipt allocation"))?;
        let owner = CapturedPrograms(Arc::new(CapturedState {
            root: config.root.try_clone_to_owned()?,
            operation: config.operation.try_clone_to_owned()?,
            root_id,
            operation_id,
            directory: Mutex::new(None),
            path,
            pin_root: config.pin_root.to_owned(),
            attachment: config.return_attachment,
            tap: config.tap_ifindex,
            namespace: current_namespace_cookie()?,
            targets: config.targets.to_vec(),
            gates,
            layout,
            installed: Mutex::new(Installed {
                objects,
                realms,
                next_candidate: 0,
                sealed: false,
                closed: false,
                complete: false,
                directory_intent: true,
            }),
        }));
        // Install the owner before the first kernel mutation so failures retain their exact prefix.
        crate::topology::check_captured_return(owner.0.tap, &owner.0.targets)?;
        for gate in &owner.0.gates {
            let target = owner
                .0
                .targets
                .iter()
                .find(|target| target.target.capture.authority.ifindex == gate.ifindex)
                .unwrap();
            let _native = target
                .target
                .attachment
                .native
                .as_ref()
                .unwrap()
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
            let mut binding = gate
                .captured
                .lock()
                .map_err(|_| invalid_data("captured attachment lock poisoned"))?;
            if binding.is_some() {
                return Err(invalid_data(
                    "captured target already has an operation owner",
                ));
            }
            *binding = Some(owner.clone());
        }
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&owner.0.path)?;
        *owner
            .0
            .directory
            .lock()
            .map_err(|_| invalid_data("captured directory receipt lock poisoned"))? =
            Some(private_bpffs(&owner.0.path)?);
        owner.state()?.directory_intent = false;
        owner.install()?;
        Ok(owner)
    }
}

pub(in crate::bpf) fn admit_config(
    target: &NativeTarget,
    config: &NativeProgramConfig<'_>,
) -> io::Result<()> {
    let registered = if let Some(native) = &target.attachment.native {
        let native = native
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        match &native.gate {
            Some(gate) => gate
                .captured
                .lock()
                .map_err(|_| invalid_data("captured attachment lock poisoned"))?
                .is_some(),
            None => false,
        }
    } else {
        false
    };
    if registered != config.captured.is_some() {
        return Err(invalid_data(
            "Native publication omits or invents its captured canonical binding",
        ));
    }
    Ok(())
}

fn check_target_xdp(target: &NativeTarget) -> io::Result<()> {
    let native = target
        .attachment
        .native
        .as_ref()
        .ok_or_else(|| invalid_data("captured target has no Native XDP owner"))?
        .lock()
        .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
    native.require_resolved()?;
    native.require_gate_with(NativeTcxAttachment::check)?;
    require_native(
        xdp_state(target.capture.authority.ifindex)?,
        native.selected_id(),
    )?;
    Ok(())
}

fn validate_targets(target: &NativeTarget, config: &CapturedProgramConfig<'_>) -> io::Result<()> {
    let namespace = current_namespace_cookie()?;
    if config.return_attachment == 0
        || config.tap_ifindex == 0
        || config.targets.is_empty()
        || config.targets.len() > MAX_CAPTURED_TARGETS
        || !config
            .targets
            .iter()
            .any(|item| std::ptr::eq(item.target.as_ref(), target))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid captured loader authority",
        ));
    }
    for (index, item) in config.targets.iter().enumerate() {
        check_target_xdp(&item.target)?;
        let authority = item.target.capture.authority;
        if !authority.is_valid()
            || authority.namespace_cookie != namespace
            || item.logical_ifindex == 0
            || item.realm_index >= config.targets.len() as u32
            || authority.ifindex == config.tap_ifindex
            || config.targets[..index].iter().any(|other| {
                other.realm_index == item.realm_index || Arc::ptr_eq(&other.target, &item.target)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unregistered or conflicting captured target",
            ));
        }
    }
    Ok(())
}

impl CapturedPrograms {
    pub fn return_attachment(&self) -> u64 {
        self.0.attachment
    }
    pub fn tap_ifindex(&self) -> u32 {
        self.0.tap
    }
    pub fn root_map_id(&self) -> u32 {
        self.0.root_id
    }
    pub fn operation_map_id(&self) -> u32 {
        self.0.operation_id
    }
    pub fn targets(&self) -> &[CapturedTarget] {
        &self.0.targets
    }
    pub fn pin_root(&self) -> &Path {
        &self.0.pin_root
    }
    pub fn realm_gate_inventory(&self) -> Vec<CapturedGateIdentity> {
        let state = self
            .0
            .installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .realms
            .iter()
            .filter_map(|gate| {
                let object = &state.objects[gate.object];
                (object.pinned || object.receipt.state == CapturedResourceState::Unpinned).then(
                    || CapturedGateIdentity {
                        resource: object.receipt.clone(),
                        realm_index: gate.realm,
                        closed_epoch: gate.epoch,
                    },
                )
            })
            .collect()
    }

    pub fn inventory(&self) -> Vec<CapturedResource> {
        let state = self
            .0
            .installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut receipts = Vec::with_capacity(state.objects.len() * 2);
        for object in &state.objects {
            if object.receipt.role.ends_with("link")
                && object.receipt.state == CapturedResourceState::Unpinned
                && !object.installed
            {
                receipts.push(CapturedResource {
                    state: CapturedResourceState::Detached,
                    ..object.receipt.clone()
                });
            }
            receipts.push(object.receipt.clone());
        }
        receipts
    }
    fn directory(&self) -> io::Result<OwnedFd> {
        self.0
            .directory
            .lock()
            .map_err(|_| invalid_data("captured directory receipt lock poisoned"))?
            .as_ref()
            .ok_or_else(|| invalid_data("captured directory creation unresolved"))?
            .try_clone()
    }
    fn state(&self) -> io::Result<std::sync::MutexGuard<'_, Installed>> {
        self.0
            .installed
            .lock()
            .map_err(|_| invalid_data("captured installation receipt lock poisoned"))
    }
    fn intend(
        &self,
        role: &'static str,
        path: PathBuf,
        kind: u32,
        ifindex: u32,
    ) -> io::Result<usize> {
        let mut state = self.state()?;
        let reusable = state.objects.iter().position(|object| {
            object.fd.is_none() && object.receipt.state == CapturedResourceState::Unpinned
        });
        let index = reusable.unwrap_or(state.objects.len());
        let object = Object {
            receipt: CapturedResource {
                role,
                pin_path: path,
                kind,
                id: 0,
                ifindex,
                state: CapturedResourceState::Installed,
            },
            fd: None,
            pinned: false,
            installed: false,
            intent: true,
            memlock: 0,
        };
        if let Some(index) = reusable {
            state.objects[index] = object;
        } else {
            state
                .objects
                .try_reserve(1)
                .map_err(|_| capacity("captured mutation receipt allocation"))?;
            state.objects.push(object);
        }
        Ok(index)
    }
    fn observe(&self, index: usize, fd: OwnedFd) -> io::Result<()> {
        let mut state = self.state()?;
        let object = &mut state.objects[index];
        object.fd = Some(fd);
        let fd = object.fd.as_ref().unwrap().as_fd();
        object.receipt.id = object_id(fd)?;
        let mut info = ProgInfo::default();
        object_info(fd, &mut info)?;
        if info.kind != object.receipt.kind {
            return Err(invalid_data("captured object kind readback mismatch"));
        }
        object.memlock = if object.receipt.role.ends_with("link") {
            if object.receipt.role == "target-entry-link" {
                self.0.layout.trace_link_bytes
            } else {
                self.0.layout.tcx_link_bytes
            }
        } else {
            usize::try_from(fd_memlock(fd)?)
                .map_err(|_| capacity("captured object memlock overflow"))?
        };
        object.intent = false;
        Ok(())
    }
    fn pin(&self, index: usize, root: BorrowedFd<'_>, name: &CStr) -> io::Result<()> {
        let mut state = self.state()?;
        let object = &mut state.objects[index];
        object.intent = true;
        pin_program(
            root,
            name,
            object
                .fd
                .as_ref()
                .ok_or_else(|| invalid_data("captured pin has no owned FD"))?
                .as_fd(),
        )?;
        object.pinned = true;
        verify_pin(root, name, object.receipt.id)?;
        object.intent = false;
        Ok(())
    }
    fn fd(&self, role: &str) -> io::Result<OwnedFd> {
        self.state()?
            .objects
            .iter()
            .find(|object| object.receipt.role == role)
            .and_then(|object| object.fd.as_ref())
            .ok_or_else(|| invalid_data("captured object receipt incomplete"))?
            .try_clone()
    }
    fn install(&self) -> io::Result<()> {
        self.pin(0, self.directory()?.as_fd(), c"operation-map")?;
        let map = self.intend(
            "realm-dispatch-map",
            self.0.path.join("realm-dispatch-map"),
            BPF_MAP_TYPE_PROG_ARRAY,
            self.0.tap,
        )?;
        self.observe(
            map,
            create_map(
                BPF_MAP_TYPE_PROG_ARRAY,
                4,
                self.0.targets.len() as u32,
                b"honk_ret_realms",
            )?,
        )?;
        self.pin(map, self.directory()?.as_fd(), c"realm-dispatch-map")?;
        let dispatch = self.fd("realm-dispatch-map")?;
        let config = CapturedProgramConfig {
            root: self.0.root.as_fd(),
            operation: self.0.operation.as_fd(),
            return_attachment: self.0.attachment,
            tap_ifindex: self.0.tap,
            targets: &self.0.targets,
            pin_root: &self.0.pin_root,
        };
        let mut log = vec![0; 1 << 20];
        for index in 0..6 {
            let program = match index {
                0 => guard(false)?,
                1 => dispatcher(&config, dispatch.as_raw_fd())?,
                2 => redirector(&config, &self.0.layout)?,
                3 => guard(true)?,
                4 => restorer(&config, &self.0.layout)?,
                _ => entry(&config, &self.0.layout)?,
            };
            let role = STATIC_ROLES[index];
            let kind = if index < 2 {
                BPF_PROG_TYPE_XDP
            } else if index == 5 {
                26
            } else {
                BPF_PROG_TYPE_SCHED_CLS
            };
            let (path, ifindex) = if index == 4 {
                (
                    self.0.gates[0].pin.with_file_name(role),
                    self.0.gates[0].ifindex,
                )
            } else {
                (
                    self.0.path.join(role),
                    if index == 5 { 0 } else { self.0.tap },
                )
            };
            let object = self.intend(role, path, kind, ifindex)?;
            let (fd, _) = if index == 5 {
                load_entry(&program, self.0.layout.entry, &mut log)?
            } else {
                load_typed_program(
                    &program,
                    STATIC_NAMES[index],
                    &mut log,
                    kind,
                    if kind == BPF_PROG_TYPE_XDP {
                        BPF_XDP
                    } else {
                        BPF_TCX_INGRESS
                    },
                )?
            };
            self.observe(object, fd)?;
            if index != 4 {
                self.pin(
                    object,
                    self.directory()?.as_fd(),
                    &CString::new(role).unwrap(),
                )?;
            }
        }
        let restorer = self.fd("native-return-restorer-prog")?;
        let restorer_id = object_id(restorer.as_fd())?;
        for gate in &self.0.gates {
            let target = self
                .0
                .targets
                .iter()
                .find(|target| target.target.capture.authority.ifindex == gate.ifindex)
                .unwrap();
            let _native = target
                .target
                .attachment
                .native
                .as_ref()
                .unwrap()
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
            require_gate_tcx(
                &query_tcx(gate.ifindex, BPF_TCX_INGRESS)?,
                &query_tcx(gate.ifindex, BPF_TCX_EGRESS)?,
                gate.program_id,
            )?;
            let program = if gate.ifindex == self.0.gates[0].ifindex {
                self.state()?
                    .objects
                    .iter()
                    .position(|object| {
                        object.receipt.role == "native-return-restorer-prog"
                            && object.receipt.ifindex == gate.ifindex
                    })
                    .unwrap()
            } else {
                let index = self.intend(
                    "native-return-restorer-prog",
                    gate.pin.with_file_name("native-return-restorer-prog"),
                    BPF_PROG_TYPE_SCHED_CLS,
                    gate.ifindex,
                )?;
                self.observe(index, restorer.try_clone()?)?;
                index
            };
            self.pin(program, gate.root.as_fd(), c"native-return-restorer-prog")?;
            let link = self.intend(
                "native-return-restorer-link",
                gate.pin.with_file_name("native-return-restorer-link"),
                11,
                gate.ifindex,
            )?;
            let before = query_tcx(gate.ifindex, BPF_TCX_INGRESS)?;
            let fd = create_tcx_link(restorer.as_fd(), gate, before.revision)?;
            self.observe(link, fd)?;
            self.state()?.objects[link].installed = true;
            self.pin(link, gate.root.as_fd(), c"native-return-restorer-link")?;
            let chain = query_tcx(gate.ifindex, BPF_TCX_INGRESS)?;
            let link_id = self.state()?.objects[link].receipt.id;
            require_return_chain(
                &chain,
                &query_tcx(gate.ifindex, BPF_TCX_EGRESS)?,
                gate.program_id,
                restorer_id,
                link_id,
            )?;
            if chain.revision <= before.revision {
                return Err(invalid_data("captured restorer revision did not advance"));
            }
        }
        let entry = self.fd("target-entry-prog")?;
        let link = self.intend(
            "target-entry-link",
            self.0.path.join("target-entry-link"),
            2,
            0,
        )?;
        self.observe(link, create_trace_link(entry.as_fd())?)?;
        self.state()?.objects[link].installed = true;
        self.pin(link, self.directory()?.as_fd(), c"target-entry-link")?;
        let tc = self.fd("tap-tcx-redirect-prog")?;
        let ingress = query_tcx(self.0.tap, BPF_TCX_INGRESS)?;
        require_empty_tcx(&ingress)?;
        require_empty_tcx(&query_tcx(self.0.tap, BPF_TCX_EGRESS)?)?;
        self.mark_intent("tap-tcx-redirect-prog", true)?;
        tcx_mutate_with(
            BPF_PROG_ATTACH,
            tc.as_fd(),
            self.0.tap,
            ingress.revision,
            duplicate_nonzero_fd,
            |command, attr| bpf(command, attr).map(|_| ()),
            || {
                require_gate_tcx(
                    &query_tcx(self.0.tap, BPF_TCX_INGRESS)?,
                    &query_tcx(self.0.tap, BPF_TCX_EGRESS)?,
                    object_id(tc.as_fd())?,
                )
            },
        )?;
        self.mark_installed("tap-tcx-redirect-prog")?;
        let guard = self.fd("tap-xdp-guard")?;
        if !xdp_absent(self.0.tap)? {
            return Err(invalid_data("foreign XDP on captured TAP"));
        }
        self.mark_intent("tap-xdp-guard", true)?;
        set_xdp(self.0.tap, guard.as_raw_fd(), None).map_err(io::Error::from)?;
        self.mark_installed("tap-xdp-guard")?;
        let data = self.fd("tap-xdp-dispatch")?;
        self.mark_intent("tap-xdp-dispatch", true)?;
        set_xdp(self.0.tap, data.as_raw_fd(), Some(guard.as_raw_fd())).map_err(io::Error::from)?;
        self.mark_installed("tap-xdp-dispatch")?;
        self.state()?.complete = true;
        self.check()
    }
    fn mark_intent(&self, role: &str, intent: bool) -> io::Result<()> {
        let mut state = self.state()?;
        let object = state
            .objects
            .iter_mut()
            .find(|object| object.receipt.role == role)
            .ok_or_else(|| invalid_data("missing captured mutation receipt"))?;
        object.intent = intent;
        Ok(())
    }
    fn mark_installed(&self, role: &str) -> io::Result<()> {
        let mut state = self.state()?;
        let object = state
            .objects
            .iter_mut()
            .find(|object| object.receipt.role == role)
            .ok_or_else(|| invalid_data("missing captured installation receipt"))?;
        object.installed = true;
        object.intent = false;
        Ok(())
    }
    fn mark_detached(&self, role: &str) -> io::Result<()> {
        let mut state = self.state()?;
        let object = state
            .objects
            .iter_mut()
            .find(|object| object.receipt.role == role)
            .ok_or_else(|| invalid_data("missing captured detach receipt"))?;
        object.installed = false;
        object.receipt.state = CapturedResourceState::Detached;
        object.intent = false;
        Ok(())
    }
    pub fn memory_bytes(&self) -> io::Result<usize> {
        let state = self.state()?;
        let mut bytes = size_of::<CapturedState>()
            .checked_add(
                state
                    .objects
                    .capacity()
                    .checked_mul(size_of::<Object>())
                    .ok_or_else(|| capacity("captured object charge overflow"))?,
            )
            .and_then(|bytes| {
                bytes.checked_add(self.0.targets.capacity() * size_of::<CapturedTarget>())
            })
            .and_then(|bytes| bytes.checked_add(state.realms.capacity() * size_of::<RealmGate>()))
            .and_then(|bytes| {
                bytes.checked_add(self.0.gates.capacity() * size_of::<Arc<NativeTcxAttachment>>())
            })
            .and_then(|bytes| bytes.checked_add(self.0.layout.cold_bytes))
            .ok_or_else(|| capacity("captured owner charge overflow"))?;
        for object in &state.objects {
            bytes = bytes
                .checked_add(object.receipt.pin_path.as_os_str().len())
                .ok_or_else(|| capacity("captured pin receipt charge overflow"))?;
            if object.receipt.role == "operation-map"
                || object.receipt.role == "realm-gate-prog"
                || object.receipt.id == 0
                || (object.receipt.role == "native-return-restorer-prog"
                    && object.receipt.ifindex != self.0.gates[0].ifindex)
            {
                continue;
            }
            bytes = bytes
                .checked_add(object.memlock)
                .ok_or_else(|| capacity("captured resident charge overflow"))?;
        }
        Ok(bytes)
    }
    pub fn check(&self) -> io::Result<()> {
        for target in &self.0.targets {
            check_target_xdp(&target.target)
                .map_err(captured_context("check: target XDP binding"))?;
        }
        crate::topology::check_captured_return(self.0.tap, &self.0.targets)
            .map_err(captured_context("check: captured return topology"))?;
        if current_namespace_cookie().map_err(captured_context("check: namespace cookie"))?
            != self.0.namespace
            || admit_map(self.0.root.as_fd(), 2, size_of::<NativeRoot>(), 1, 1 << 10)
                .map_err(captured_context("check: root map info"))?
                != self.0.root_id
            || admit_map(
                self.0.operation.as_fd(),
                2,
                size_of::<NativeCapturedOperation>(),
                1,
                1 << 10,
            )
            .map_err(captured_context("check: operation map info"))?
                != self.0.operation_id
        {
            return Err(invalid_data("captured namespace or cell binding changed"));
        }
        let state = self.state()?;
        if !state.complete
            || state.closed
            || state.directory_intent
            || state.objects.iter().any(|object| object.intent)
        {
            return Err(invalid_data(
                "captured installation has an unresolved prefix",
            ));
        }
        let mut entry_link_seen = false;
        let mut entry_program_seen = false;
        let mut entry_program_id = None;
        for object in &state.objects {
            let is_entry_link = object.receipt.role == "target-entry-link";
            let is_entry_program = object.receipt.role == "target-entry-prog";
            if is_entry_link || is_entry_program {
                if object.receipt.state != CapturedResourceState::Installed
                    || object.receipt.id == 0
                    || object.fd.is_none()
                    || !object.pinned
                    || (is_entry_link && !object.installed)
                {
                    return Err(captured_context(MISSING_ENTRY_CHECK_STEP)(
                        io::ErrorKind::InvalidData.into(),
                    ));
                }
                if is_entry_link {
                    if entry_link_seen {
                        return Err(captured_context(MISSING_ENTRY_CHECK_STEP)(
                            io::ErrorKind::InvalidData.into(),
                        ));
                    }
                    entry_link_seen = true;
                } else {
                    if entry_program_seen {
                        return Err(captured_context(MISSING_ENTRY_CHECK_STEP)(
                            io::ErrorKind::InvalidData.into(),
                        ));
                    }
                    entry_program_seen = true;
                    entry_program_id = Some(object.receipt.id);
                }
            }
            if object.receipt.state == CapturedResourceState::Unpinned {
                continue;
            }
            if object.receipt.id == 0 || object.fd.is_none() {
                return Err(invalid_data("captured inventory incomplete"));
            }
            if is_entry_link {
                #[repr(C)]
                #[derive(Default)]
                struct TraceInfo {
                    kind: u32,
                    id: u32,
                    program: u32,
                    pad: u32,
                    attach: u32,
                    object: u32,
                    target: u32,
                    reserved: u32,
                    cookie: u64,
                }
                let mut info = TraceInfo::default();
                object_info(object.fd.as_ref().unwrap().as_fd(), &mut info)
                    .map_err(captured_context("check: entry tracing link info"))?;
                if info.kind != 2
                    || info.id != object.receipt.id
                    || info.program != entry_program_id.unwrap_or(0)
                    || info.attach != 24
                    || info.target != self.0.layout.entry
                {
                    return Err(invalid_data("captured target entry attachment changed"));
                }
            }
            if object.pinned {
                let parent = object
                    .receipt
                    .pin_path
                    .parent()
                    .ok_or_else(|| invalid_data("captured pin has no parent"))?;
                let root =
                    private_bpffs(parent).map_err(captured_context("check: open pin parent"))?;
                let name = CString::new(
                    object
                        .receipt
                        .pin_path
                        .file_name()
                        .unwrap()
                        .as_encoded_bytes(),
                )
                .map_err(|_| invalid_data("invalid captured pin name"))?;
                verify_pin(root.as_fd(), &name, object.receipt.id)
                    .map_err(captured_context("check: verify owned pin"))?;
            }
        }
        if !entry_link_seen || !entry_program_seen {
            return Err(captured_context(MISSING_ENTRY_CHECK_STEP)(
                io::ErrorKind::InvalidData.into(),
            ));
        }
        let sealed = state.sealed;
        let selected = state
            .objects
            .iter()
            .find(|object| {
                object.receipt.role
                    == if sealed {
                        "tap-xdp-guard"
                    } else {
                        "tap-xdp-dispatch"
                    }
            })
            .unwrap()
            .receipt
            .id;
        let tc = state
            .objects
            .iter()
            .find(|object| {
                object.receipt.role
                    == if sealed {
                        "tap-tcx-guard-prog"
                    } else {
                        "tap-tcx-redirect-prog"
                    }
            })
            .unwrap()
            .receipt
            .id;
        let dispatch = state
            .objects
            .iter()
            .find(|object| object.receipt.role == "realm-dispatch-map")
            .unwrap()
            .fd
            .as_ref()
            .unwrap();
        admit_map(
            dispatch.as_fd(),
            BPF_MAP_TYPE_PROG_ARRAY,
            4,
            self.0.targets.len() as u32,
            0,
        )
        .map_err(captured_context("check: realm dispatch map info"))?;
        for realm in state.realms.iter().filter(|realm| realm.selected) {
            let id: u32 = map_value(dispatch.as_fd(), &realm.realm)
                .map_err(captured_context("check: realm dispatch lookup"))?;
            if id != state.objects[realm.object].receipt.id {
                return Err(invalid_data("captured canonical selection changed"));
            }
        }
        drop(state);
        require_native(
            xdp_state(self.0.tap).map_err(captured_context("check: TAP XDP state"))?,
            selected,
        )
        .map_err(captured_context("check: TAP XDP binding"))?;
        require_gate_tcx(
            &query_tcx(self.0.tap, BPF_TCX_INGRESS)
                .map_err(captured_context("check: TAP ingress TCX query"))?,
            &query_tcx(self.0.tap, BPF_TCX_EGRESS)
                .map_err(captured_context("check: TAP egress TCX query"))?,
            tc,
        )
        .map_err(captured_context("check: TAP TCX binding"))?;
        for gate in &self.0.gates {
            gate.check()
                .map_err(captured_context("check: target canonical gate"))?;
        }
        Ok(())
    }
    pub(in crate::bpf) fn check_target_chain(
        &self,
        gate: &NativeTcxAttachment,
        ingress: &TcxChain,
        egress: &TcxChain,
    ) -> io::Result<()> {
        let state = self.state()?;
        let program = state.objects.iter().find(|object| {
            object.receipt.role == "native-return-restorer-prog"
                && object.receipt.ifindex == gate.ifindex
        });
        let link = state.objects.iter().find(|object| {
            object.receipt.role == "native-return-restorer-link"
                && object.receipt.ifindex == gate.ifindex
        });
        match (program, link) {
            (Some(program), Some(link)) if link.installed && !link.intent => {
                verify_pin(
                    gate.root.as_fd(),
                    c"native-return-restorer-prog",
                    program.receipt.id,
                )
                .map_err(captured_context("check: verify restorer program pin"))?;
                verify_pin(
                    gate.root.as_fd(),
                    c"native-return-restorer-link",
                    link.receipt.id,
                )
                .map_err(captured_context("check: verify restorer link pin"))?;
                let mut info = LinkInfo::default();
                object_info(
                    link.fd
                        .as_ref()
                        .ok_or_else(|| invalid_data("captured restorer link FD missing"))?
                        .as_fd(),
                    &mut info,
                )
                .map_err(captured_context("check: target TCX restorer link info"))?;
                if info.kind != 11
                    || info.id != link.receipt.id
                    || info.prog_id != program.receipt.id
                    || info.ifindex != gate.ifindex
                {
                    return Err(invalid_data("captured restorer link binding changed"));
                }
                require_return_chain(
                    ingress,
                    egress,
                    gate.program_id,
                    program.receipt.id,
                    link.receipt.id,
                )
            }
            (None, None) if !state.complete => require_gate_tcx(ingress, egress, gate.program_id),
            _ => Err(invalid_data(
                "captured target restorer installation unresolved",
            )),
        }
    }
    fn common_updates(&self) -> io::Result<Option<NativeXdpUpdates>> {
        let mut common: Option<NativeXdpUpdates> = None;
        let mut unbound = false;
        if self.0.targets.is_empty() {
            return Err(invalid_data("captured close has no target owner"));
        }
        for (index, target) in self.0.targets.iter().enumerate() {
            let native = target
                .target
                .attachment
                .native
                .as_ref()
                .ok_or_else(|| invalid_data("captured target has no Native XDP owner"))?;
            if self.0.targets[..index].iter().any(|other| {
                other
                    .target
                    .attachment
                    .native
                    .as_ref()
                    .is_some_and(|other| Arc::ptr_eq(native, other))
            }) {
                return Err(invalid_data("captured close has duplicate target owners"));
            }
            let updates = native
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))?
                .updates
                .clone();
            match updates {
                Some(updates) => {
                    if unbound
                        || common
                            .as_ref()
                            .is_some_and(|common| !common.same_authority(&updates))
                    {
                        return Err(invalid_data(
                            "captured targets have mixed or partial Native watch binding",
                        ));
                    }
                    common = Some(updates);
                }
                None => {
                    if common.is_some() {
                        return Err(invalid_data(
                            "captured targets have partial Native watch binding",
                        ));
                    }
                    unbound = true;
                }
            }
        }
        Ok(common)
    }

    fn seal_xdp(&self, updates: Option<&NativeXdpUpdates>) -> io::Result<()> {
        let data = self
            .fd("tap-xdp-dispatch")
            .map_err(captured_context("close: seal dispatch FD"))?;
        let guard = self
            .fd("tap-xdp-guard")
            .map_err(captured_context("close: seal XDP guard FD"))?;
        let guard_id =
            object_id(guard.as_fd()).map_err(captured_context("close: seal XDP guard ID"))?;
        let mut watch = updates.map(NativeXdpUpdates::lock);
        let state = xdp_state(self.0.tap).map_err(captured_context("close: seal XDP state"))?;
        if state.prog_id == guard_id {
            require_native(state, guard_id)
                .map_err(captured_context("close: seal existing XDP guard binding"))?;
            self.state()?.sealed = true;
            return watch.as_mut().map_or(Ok(()), |watch| watch.check());
        }
        let data_id =
            object_id(data.as_fd()).map_err(captured_context("close: seal XDP dispatch ID"))?;
        require_native(state, data_id).map_err(captured_context("close: seal XDP binding"))?;
        self.mark_intent("tap-xdp-guard", true)?;
        let outcome = watch.as_mut().map_or_else(
            || NativeUpdateOutcome {
                transport: set_xdp(self.0.tap, guard.as_raw_fd(), Some(data.as_raw_fd())),
                observation: Ok(()),
            },
            |watch| {
                watch.update(
                    self.0.tap,
                    guard.as_fd(),
                    guard_id,
                    data.as_fd(),
                    data_id,
                    true,
                )
            },
        );
        let acknowledged = outcome.transport.is_ok();
        let operation = outcome
            .transport
            .map_err(io::Error::from)
            .map_err(captured_context("close: seal XDP replacement"));
        let bookkeeping = if acknowledged {
            self.mark_installed("tap-xdp-guard").and_then(|()| {
                self.state()?.sealed = true;
                Ok(())
            })
        } else {
            Ok(())
        };
        let readback = if acknowledged {
            xdp_state(self.0.tap)
                .and_then(|state| require_native(state, guard_id))
                .map(|_| ())
                .map_err(captured_context("close: seal XDP replacement readback"))
        } else {
            Ok(())
        };
        let result = combine_observation(combine_observation(operation, bookkeeping), readback);
        if acknowledged
            && result.is_err()
            && let Some(watch) = &mut watch
        {
            watch.invalidate();
        }
        combine_observation(result, outcome.observation)
    }

    pub fn seal(&self) -> io::Result<()> {
        let common = self.common_updates();
        let native = self
            .0
            .targets
            .first()
            .and_then(|target| target.target.attachment.native.as_ref())
            .ok_or_else(|| invalid_data("captured close has no Native XDP owner"))?
            .lock();
        let (native, lock_result) = match native {
            Ok(native) => (native, Ok(())),
            Err(poisoned) => (
                poisoned.into_inner(),
                Err(invalid_data("Native attachment lock poisoned")),
            ),
        };
        // Failed composition still permits exact-old containment, never watched success.
        let xdp = match common {
            Ok(updates) => self.seal_xdp(updates.as_ref()),
            Err(error) => combine_observation(self.seal_xdp(None), Err(error)),
        };
        let tcx = self.replace_tcx_guard();
        drop(native);
        let result = combine_observation(combine_observation(xdp, tcx), lock_result);
        combine_observation(
            result,
            self.check()
                .map_err(captured_context("close: seal readback")),
        )
    }
    /// Close the actual exclusive TAP only after its private hooks have joined.
    pub fn close_tap(&self, fd: RawFd, close: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let updates = self.common_updates()?;
        let _native = self.0.targets[0]
            .target
            .attachment
            .native
            .as_ref()
            .unwrap()
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        {
            let state = self.state()?;
            if !state.closed
                || state
                    .objects
                    .iter()
                    .any(|object| object.intent || object.pinned)
            {
                return Err(invalid_data(
                    "captured TAP close requires joined private hooks",
                ));
            }
        }
        if current_namespace_cookie()? != self.0.namespace
            || admit_map(self.0.root.as_fd(), 2, size_of::<NativeRoot>(), 1, 1 << 10)?
                != self.0.root_id
            || admit_map(
                self.0.operation.as_fd(),
                2,
                size_of::<NativeCapturedOperation>(),
                1,
                1 << 10,
            )? != self.0.operation_id
        {
            return Err(invalid_data(
                "captured TAP namespace or map identity changed",
            ));
        }
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        // The caller retains the FD until the synchronous callback is invoked.
        if unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut name = [0u8; libc::IFNAMSIZ];
        for (out, byte) in name.iter_mut().zip(request.ifr_name) {
            *out = byte as u8;
        }
        let name = CStr::from_bytes_until_nul(&name)
            .map_err(|_| invalid_data("captured TAP FD has malformed name"))?;
        let flags = u32::from(unsafe { request.ifr_ifru.ifru_flags } as u16);
        if name.to_bytes().is_empty()
            || flags & !(libc::IFF_TUN_EXCL as u32 | 0x8000)
                != (libc::IFF_TAP | libc::IFF_NO_PI) as u32
            || unsafe { libc::if_nametoindex(name.as_ptr()) } != self.0.tap
        {
            return Err(invalid_data(
                "captured TAP FD does not own the admitted private device",
            ));
        }
        let raw = unsafe { libc::ioctl(fd, libc::TUNGETDEVNETNS) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let namespace = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) }).metadata()?;
        let current = std::fs::metadata("/proc/thread-self/ns/net")?;
        if (namespace.dev(), namespace.ino()) != (current.dev(), current.ino()) {
            return Err(invalid_data("captured TAP FD belongs to another namespace"));
        }
        crate::topology::check_captured_return(self.0.tap, &self.0.targets)
            .map_err(captured_context("close: TAP topology authentication"))?;
        require_empty_tcx(&query_tcx(self.0.tap, BPF_TCX_INGRESS)?)?;
        require_empty_tcx(&query_tcx(self.0.tap, BPF_TCX_EGRESS)?)?;
        if !xdp_absent(self.0.tap)
            .map_err(captured_context("close: TAP XDP absence authentication"))?
        {
            return Err(invalid_data(
                "captured TAP close found a foreign XDP selection",
            ));
        }
        if let Some(updates) = updates {
            let outcome = updates.lock().close_private_tap(self.0.tap, close);
            combine_observation(
                outcome.transport.map_err(io::Error::from),
                outcome.observation,
            )
            .map_err(captured_context("close: owned TAP FD transaction"))
        } else {
            close().map_err(captured_context("close: owned TAP FD"))?;
            match xdp_state(self.0.tap) {
                Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(()),
                Err(error) => Err(captured_context("close: TAP absence readback")(error)),
                Ok(_) => Err(invalid_data(
                    "captured TAP still exists after owned FD close",
                )),
            }
        }
    }

    pub fn finish_close(&self) -> io::Result<bool> {
        if self.state()?.closed {
            return self
                .common_updates()?
                .map_or(Ok(true), |updates| updates.lock().check().map(|()| true));
        }
        self.seal()?;
        let updates = self.common_updates()?;
        let operation: NativeCapturedOperation = map_value(self.0.operation.as_fd(), &0)
            .map_err(captured_context("close: operation lookup"))?;
        if !matches!(
            operation.phase,
            0 | NATIVE_OP_PREPARED | NATIVE_OP_GATE_REFUSED | NATIVE_OP_ENTERED
        ) {
            return Ok(false);
        }
        if operation.phase == NATIVE_OP_ENTERED
            && (operation.receipt != 1
                || operation.entry_seq != 1
                || operation.return_attachment != self.0.attachment
                || operation.op_incarnation == 0)
        {
            return Err(invalid_data(
                "captured close has a foreign or partial entry receipt",
            ));
        }
        // C calls only after the producer and this operation's fresh Grace have joined.
        for gate in &self.0.gates {
            let target = self
                .0
                .targets
                .iter()
                .find(|target| target.target.capture.authority.ifindex == gate.ifindex)
                .unwrap();
            let _native = target
                .target
                .attachment
                .native
                .as_ref()
                .unwrap()
                .lock()
                .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
            let mut state = self.state()?;
            let object = state
                .objects
                .iter_mut()
                .find(|object| {
                    object.receipt.role == "native-return-restorer-link"
                        && object.receipt.ifindex == gate.ifindex
                })
                .ok_or_else(|| invalid_data("missing captured restorer link"))?;
            if object.installed {
                object.intent = true;
                detach_link(object.fd.as_ref().unwrap().as_fd())
                    .map_err(captured_context("close: detach target TCX restorer"))?;
                require_gate_tcx(
                    &query_tcx(gate.ifindex, BPF_TCX_INGRESS)
                        .map_err(captured_context("close: target ingress TCX readback"))?,
                    &query_tcx(gate.ifindex, BPF_TCX_EGRESS)
                        .map_err(captured_context("close: target egress TCX readback"))?,
                    gate.program_id,
                )
                .map_err(captured_context("close: target TCX detach binding"))?;
                object.installed = false;
                object.receipt.state = CapturedResourceState::Detached;
                object.intent = false;
            }
        }
        let _native = self.0.targets[0]
            .target
            .attachment
            .native
            .as_ref()
            .unwrap()
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        let tc = self
            .fd("tap-tcx-guard-prog")
            .map_err(captured_context("close: TAP TCX guard FD"))?;
        let ingress = query_tcx(self.0.tap, BPF_TCX_INGRESS)
            .map_err(captured_context("close: TAP ingress TCX query"))?;
        self.mark_intent("tap-tcx-guard-prog", true)?;
        tcx_mutate_with(
            BPF_PROG_DETACH,
            tc.as_fd(),
            self.0.tap,
            ingress.revision,
            |fd| {
                duplicate_nonzero_fd(fd)
                    .map_err(captured_context("close: duplicate TAP TCX detach FD"))
            },
            |command, attr| {
                bpf(command, attr)
                    .map(|_| ())
                    .map_err(captured_context("close: detach TAP TCX guard"))?;
                self.mark_detached("tap-tcx-guard-prog")
            },
            || {
                require_empty_tcx(
                    &query_tcx(self.0.tap, BPF_TCX_INGRESS)
                        .map_err(captured_context("close: TAP TCX detach readback"))?,
                )
            },
        )
        .map_err(captured_context("close: TAP TCX detach join"))?;
        let guard = self
            .fd("tap-xdp-guard")
            .map_err(captured_context("close: TAP XDP guard FD"))?;
        let guard_id =
            object_id(guard.as_fd()).map_err(captured_context("close: TAP XDP guard ID"))?;
        self.mark_intent("tap-xdp-guard", true)?;
        let outcome = if let Some(updates) = &updates {
            updates
                .lock()
                .detach_private_xdp(self.0.tap, guard.as_fd(), guard_id)
        } else {
            NativeUpdateOutcome {
                transport: set_xdp(self.0.tap, -1, Some(guard.as_raw_fd())),
                observation: Ok(()),
            }
        };
        let bookkeeping = if outcome.transport.is_ok() {
            self.mark_detached("tap-xdp-guard")
        } else {
            Ok(())
        };
        combine_observation(
            combine_observation(outcome.transport.map_err(io::Error::from), bookkeeping),
            outcome.observation,
        )
        .map_err(captured_context("close: detach TAP XDP guard"))?;
        if !xdp_absent(self.0.tap).map_err(captured_context("close: TAP XDP detach readback"))? {
            return Err(invalid_data("captured close: TAP XDP detach did not join"));
        }
        let mut state = self.state()?;
        let entry_link = state
            .objects
            .iter()
            .find(|object| object.receipt.role == "target-entry-link")
            .ok_or_else(|| invalid_data("captured close: entry link receipt missing"))?
            .receipt
            .id;
        let entry_program = state
            .objects
            .iter()
            .find(|object| object.receipt.role == "target-entry-prog")
            .ok_or_else(|| invalid_data("captured close: entry program receipt missing"))?
            .receipt
            .id;
        for object in state.objects.iter_mut().rev() {
            unpin_captured_object(object)?;
            if matches!(
                object.receipt.role,
                "target-entry-link" | "target-entry-prog"
            ) {
                close_entry_fd(object)?;
            }
        }
        drop(state);
        drop(_native);
        if !join_tracing_release(entry_link, entry_program)? {
            return Ok(false);
        }
        let mut state = self.state()?;
        for object in &mut state.objects {
            if matches!(
                object.receipt.role,
                "target-entry-link" | "target-entry-prog"
            ) {
                object.installed = false;
                object.receipt.state = CapturedResourceState::Unpinned;
                object.intent = false;
            }
        }
        state.closed = true;
        drop(state);
        for gate in &self.0.gates {
            let mut binding = gate
                .captured
                .lock()
                .map_err(|_| invalid_data("captured attachment lock poisoned"))?;
            *binding = None;
        }
        Ok(true)
    }
}

impl CapturedPrograms {
    fn replace_tcx_guard(&self) -> io::Result<()> {
        let tc = self
            .fd("tap-tcx-redirect-prog")
            .map_err(captured_context("close: seal TCX redirect FD"))?;
        let guard = self
            .fd("tap-tcx-guard-prog")
            .map_err(captured_context("close: seal TCX guard FD"))?;
        let guard_id =
            object_id(guard.as_fd()).map_err(captured_context("close: seal TCX guard ID"))?;
        let ingress = query_tcx(self.0.tap, BPF_TCX_INGRESS)
            .map_err(captured_context("close: seal ingress TCX query"))?;
        let egress = query_tcx(self.0.tap, BPF_TCX_EGRESS)
            .map_err(captured_context("close: seal egress TCX query"))?;
        if ingress.count == 1 && ingress.programs[0] == guard_id {
            return require_gate_tcx(&ingress, &egress, guard_id)
                .map_err(captured_context("close: seal existing TCX guard binding"));
        }
        let tc_id =
            object_id(tc.as_fd()).map_err(captured_context("close: seal TCX redirect ID"))?;
        require_gate_tcx(&ingress, &egress, tc_id)
            .map_err(captured_context("close: seal TCX redirect binding"))?;
        self.mark_intent("tap-tcx-guard-prog", true)?;
        bpf(
            BPF_PROG_ATTACH,
            &mut TcxAttachAttr {
                target_ifindex: self.0.tap,
                attach_bpf_fd: guard.as_raw_fd() as u32,
                attach_type: BPF_TCX_INGRESS,
                attach_flags: BPF_F_REPLACE,
                replace_bpf_fd: tc.as_raw_fd() as u32,
                expected_revision: ingress.revision,
                ..TcxAttachAttr::default()
            },
        )
        .map_err(captured_context("close: seal TCX replacement"))?;
        let bookkeeping = self.mark_installed("tap-tcx-guard-prog");
        let readback = (|| {
            require_gate_tcx(
                &query_tcx(self.0.tap, BPF_TCX_INGRESS).map_err(captured_context(
                    "close: seal ingress TCX replacement readback",
                ))?,
                &query_tcx(self.0.tap, BPF_TCX_EGRESS).map_err(captured_context(
                    "close: seal egress TCX replacement readback",
                ))?,
                guard_id,
            )
            .map_err(captured_context("close: seal TCX replacement binding"))
        })();
        combine_observation(bookkeeping, readback)
    }

    #[cfg(feature = "captured-fault")]
    pub fn refuse_after_admission_for_test(&self) -> io::Result<()> {
        let _native = self.0.targets[0]
            .target
            .attachment
            .native
            .as_ref()
            .unwrap()
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        // This real TCX replacement leaves pre-tap canonical admission in place.
        self.replace_tcx_guard()
    }
    #[cfg(feature = "captured-fault")]
    pub fn remove_entry_witness_for_test(&self) -> io::Result<()> {
        self.check()?;
        let (link_index, program_index, link_id, program_id) = {
            let mut state = self.state()?;
            if !state.complete
                || state.closed
                || state.sealed
                || state.directory_intent
                || state.objects.iter().any(|object| object.intent)
            {
                return Err(invalid_data(
                    "captured missing-entry control requires an active owner",
                ));
            }
            let link_index = state
                .objects
                .iter()
                .position(|object| object.receipt.role == "target-entry-link")
                .ok_or_else(|| invalid_data("captured entry link receipt missing"))?;
            let program_index = state
                .objects
                .iter()
                .position(|object| object.receipt.role == "target-entry-prog")
                .ok_or_else(|| invalid_data("captured entry program receipt missing"))?;
            let link_id = state.objects[link_index].receipt.id;
            let program_id = state.objects[program_index].receipt.id;
            for index in [link_index, program_index] {
                let object = &mut state.objects[index];
                unpin_captured_object(object)?;
                close_entry_fd(object)?;
            }
            (link_index, program_index, link_id, program_id)
        };
        if !join_tracing_release(link_id, program_id)? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "captured entry witness release did not join",
            ));
        }
        let mut state = self.state()?;
        for index in [link_index, program_index] {
            state.objects[index].installed = false;
            state.objects[index].intent = false;
        }
        Ok(())
    }

    #[cfg(feature = "captured-fault")]
    pub fn is_missing_entry_readback_error_for_test(error: &io::Error) -> bool {
        if error.kind() != io::ErrorKind::InvalidData {
            return false;
        }
        let Some(outer) = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<CapturedStepError>())
        else {
            return false;
        };
        if outer.step != "close: seal readback" {
            return false;
        }
        let Some(inner) = outer
            .source
            .get_ref()
            .and_then(|source| source.downcast_ref::<CapturedStepError>())
        else {
            return false;
        };
        inner.step == MISSING_ENTRY_CHECK_STEP
            && inner.source.kind() == io::ErrorKind::InvalidData
            && inner.source.get_ref().is_none()
    }

    #[cfg(feature = "captured-fault")]
    pub fn check_missing_entry_containment_for_test(&self) -> io::Result<()> {
        let updates = self
            .common_updates()?
            .ok_or_else(|| invalid_data("captured missing-entry owner has no common XDP watch"))?;
        updates.lock().check()?;
        for target in &self.0.targets {
            check_target_xdp(&target.target)?;
        }
        crate::topology::check_captured_return(self.0.tap, &self.0.targets)?;
        {
            let state = self.state()?;
            if !state.complete
                || !state.sealed
                || state.closed
                || state.directory_intent
                || state.objects.iter().any(|object| object.intent)
            {
                return Err(invalid_data(
                    "captured missing-entry containment is unresolved",
                ));
            }
        }
        let xdp = self.fd("tap-xdp-guard")?;
        let tcx = self.fd("tap-tcx-guard-prog")?;
        require_native(xdp_state(self.0.tap)?, object_id(xdp.as_fd())?)?;
        require_gate_tcx(
            &query_tcx(self.0.tap, BPF_TCX_INGRESS)?,
            &query_tcx(self.0.tap, BPF_TCX_EGRESS)?,
            object_id(tcx.as_fd())?,
        )?;
        for gate in &self.0.gates {
            gate.check()?;
        }
        updates.lock().check()
    }
}

fn unpin_captured_object(object: &mut Object) -> io::Result<()> {
    if object.pinned {
        let root = private_bpffs(object.receipt.pin_path.parent().unwrap())
            .map_err(captured_context("close: open pin parent"))?;
        let name = CString::new(
            object
                .receipt
                .pin_path
                .file_name()
                .unwrap()
                .as_encoded_bytes(),
        )
        .unwrap();
        verify_pin(root.as_fd(), &name, object.receipt.id)
            .map_err(captured_context("close: verify owned pin before unlink"))?;
        object.intent = true;
        // SAFETY: root owns the admitted directory and name is a verified NUL-terminated pin name.
        if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(captured_context("close: unlink owned pin")(
                io::Error::last_os_error(),
            ));
        }
        object.pinned = false;
        object.receipt.state = CapturedResourceState::Unpinned;
        if !matches!(
            object.receipt.role,
            "target-entry-link" | "target-entry-prog"
        ) {
            object.intent = false;
        }
    }
    Ok(())
}

fn close_entry_fd(object: &mut Object) -> io::Result<()> {
    object.intent = true;
    let step = if object.receipt.role == "target-entry-link" {
        "close: close entry tracing link FD"
    } else {
        "close: close entry tracing program FD"
    };
    let fd = object
        .fd
        .take()
        .ok_or_else(|| invalid_data("captured close: entry object FD missing"))?;
    let fd = std::os::fd::IntoRawFd::into_raw_fd(fd);
    // SAFETY: fd is uniquely owned. Linux consumes it even on errors; never retry.
    if unsafe { libc::close(fd) } != 0 {
        return Err(captured_context(step)(io::Error::last_os_error()));
    }
    Ok(())
}

fn join_tracing_release(entry_link: u32, entry_program: u32) -> io::Result<bool> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        #[repr(C)]
        struct Id {
            id: u32,
            next: u32,
            flags: u32,
        }
        let link = bpf_fd(
            30,
            &mut Id {
                id: entry_link,
                next: 0,
                flags: 0,
            },
        );
        let program = bpf_fd(
            13,
            &mut Id {
                id: entry_program,
                next: 0,
                flags: 0,
            },
        );
        // Link release unlinks the trampoline before prog_put; only both absent IDs prove completion.
        if tracing_release_complete(link, program)? {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::yield_now();
    }
}

#[derive(Debug)]
struct CapturedStepError {
    step: &'static str,
    source: io::Error,
}

impl std::fmt::Display for CapturedStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "captured {}: {}", self.step, self.source)
    }
}

impl std::error::Error for CapturedStepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn captured_context(step: &'static str) -> impl FnOnce(io::Error) -> io::Error {
    move |source| io::Error::new(source.kind(), CapturedStepError { step, source })
}
const MISSING_ENTRY_CHECK_STEP: &str = "check: active entry witness";

fn tracing_release_complete(
    link: io::Result<OwnedFd>,
    program: io::Result<OwnedFd>,
) -> io::Result<bool> {
    let absent = |result: io::Result<OwnedFd>, step| match result {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(true),
        Err(error) => Err(captured_context(step)(error)),
        Ok(_) => Ok(false),
    };
    let link_absent = absent(link, "close: entry tracing link ID release proof")?;
    let program_absent = absent(program, "close: entry tracing program ID release proof")?;
    Ok(link_absent && program_absent)
}

fn verify_pin(root: BorrowedFd<'_>, name: &CStr, expected: u32) -> io::Result<()> {
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
    )
    .map_err(captured_context("pin: get pinned object FD"))?;
    if object_id(fd.as_fd()).map_err(captured_context("pin: pinned object ID"))? != expected {
        return Err(invalid_data("captured pin identity changed"));
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
        .map_err(captured_context("pin: pinned object fdinfo"))?;
    let class = if name.to_bytes().ends_with(b"-link") {
        "link_id:"
    } else if name.to_bytes().ends_with(b"-map") {
        "map_id:"
    } else {
        "prog_id:"
    };
    let mut ids = info.lines().filter_map(|line| line.strip_prefix(class));
    if ids.next().and_then(|id| id.trim().parse::<u32>().ok()) != Some(expected)
        || ids.next().is_some()
    {
        return Err(invalid_data("captured pin object class changed"));
    }
    Ok(())
}

fn require_return_chain(
    ingress: &TcxChain,
    egress: &TcxChain,
    gate: u32,
    restorer: u32,
    link: u32,
) -> io::Result<()> {
    if gate == 0
        || restorer == 0
        || link == 0
        || ingress.count != 2
        || ingress.revision == 0
        || ingress.programs[..2] != [restorer, gate]
        || ingress.links[..2] != [link, 0]
    {
        return Err(invalid_data(
            "captured target is not the exact owned restorer/gate chain",
        ));
    }
    require_empty_tcx(egress)
}

fn create_tcx_link(
    program: BorrowedFd<'_>,
    gate: &NativeTcxAttachment,
    revision: u64,
) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct Attr {
        program: u32,
        target: u32,
        kind: u32,
        flags: u32,
        relative: u32,
        pad: u32,
        revision: u64,
    }
    bpf_fd(
        BPF_LINK_CREATE,
        &mut Attr {
            program: program.as_raw_fd() as u32,
            target: gate.ifindex,
            kind: BPF_TCX_INGRESS,
            flags: 1 << 3,
            relative: gate.program.as_raw_fd() as u32,
            pad: 0,
            revision,
        },
    )
}
fn create_trace_link(program: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    bpf_fd(
        BPF_LINK_CREATE,
        &mut LinkCreateAttr {
            prog_fd: program.as_raw_fd() as u32,
            target_ifindex: 0,
            attach_type: 24,
            flags: 0,
        },
    )
}
fn detach_link(fd: BorrowedFd<'_>) -> io::Result<()> {
    #[repr(C)]
    struct Attr {
        fd: u32,
    }
    bpf(
        34,
        &mut Attr {
            fd: fd.as_raw_fd() as u32,
        },
    )
    .map(|_| ())
}

fn load_entry(program: &Program, entry: u32, log: &mut [u8]) -> io::Result<(OwnedFd, u32)> {
    log.fill(0);
    let fd = bpf_fd(
        BPF_PROG_LOAD,
        &mut ProgLoadAttr {
            prog_type: 26,
            insn_cnt: program.len as u32,
            insns: program.insns.as_ptr() as u64,
            license: c"GPL".as_ptr() as u64,
            log_level: 1,
            log_size: log.len() as u32,
            log_buf: log.as_mut_ptr() as u64,
            prog_name: object_name(STATIC_NAMES[5]),
            expected_attach_type: 24,
            attach_btf_id: entry,
            ..ProgLoadAttr::default()
        },
    )?;
    let id = object_id(fd.as_fd())?;
    Ok((fd, id))
}

fn static_finish(a: Asm) -> io::Result<Program> {
    let mut program = a.finish()?;
    if program.len > STATIC_LIMIT {
        return Err(capacity(
            "captured static program exceeds charged instruction bound",
        ));
    }
    program.flags |= 1 << 5;
    Ok(program)
}
fn guard(tc: bool) -> io::Result<Program> {
    let mut a = Asm::new();
    a.exit(if tc { 2 } else { XDP_DROP });
    let mut program = static_finish(a)?;
    if tc {
        program.flags = 0;
    }
    Ok(program)
}
fn equals64(a: &mut Asm, base: u8, offset: i16, value: u64, failure: Target) {
    a.emit(LDX_DW, 0, base, offset, 0);
    a.imm(1, value);
    a.jump(JNE_X, 0, 1, 0, failure);
}
fn op(a: &mut Asm, config: &CapturedProgramConfig<'_>, failure: Target) {
    a.emit(ST_W, 10, 0, INDEX, 0);
    a.lookup(config.operation.as_raw_fd(), INDEX);
    a.jump(JEQ_K, 0, 0, 0, failure);
    a.mov(8, 0);
    equals64(a, 8, 8, config.return_attachment, failure);
    a.emit(LDX_DW, 0, 8, 0, 0);
    a.jump(JEQ_K, 0, 0, 0, failure);
}
fn phase_cas(a: &mut Asm, base: u8, from: u32, to: u32, failure: Target) {
    a.emit(MOV_K, 0, 0, 0, from as i32);
    a.emit(MOV_K, 1, 0, 0, to as i32);
    a.emit(CMPXCHG_W, base, 1, PHASE, CMPXCHG_DW);
    a.jump(JNE_K, 0, 0, from as i32, failure);
}
fn dispatcher(config: &CapturedProgramConfig<'_>, programs: RawFd) -> io::Result<Program> {
    let mut a = Asm::new();
    let drop = a.label();
    let refuse = a.label();
    a.mov(9, 1);
    a.emit(LDX_W, 0, 9, 12, 0);
    a.jump(JNE32_K, 0, 0, config.tap_ifindex as i32, drop);
    op(&mut a, config, drop);
    phase_cas(&mut a, 8, NATIVE_OP_PREPARED, NATIVE_OP_ADMITTING, drop);
    a.emit(LDX_W, 3, 8, 176, 0);
    a.jump(JGE_K, 3, 0, config.targets.len() as i32, refuse);
    a.b.map_fd(programs);
    a.mov(2, 1);
    a.mov(1, 9);
    a.emit(CALL, 0, 0, 0, 12);
    a.bind(refuse);
    phase_cas(&mut a, 8, NATIVE_OP_ADMITTING, NATIVE_OP_GATE_REFUSED, drop);
    a.bind(drop);
    a.exit(XDP_DROP);
    static_finish(a)
}
fn redirector(
    config: &CapturedProgramConfig<'_>,
    layout: &layout::CapturedLayout,
) -> io::Result<Program> {
    let mut a = Asm::new();
    let drop = a.label();
    a.mov(9, 1);
    a.emit(LDX_W, 0, 9, 36, 0);
    a.jump(JNE32_K, 0, 0, config.tap_ifindex as i32, drop);
    op(&mut a, config, drop);
    phase_cas(&mut a, 8, NATIVE_OP_ADMITTED, NATIVE_OP_REDIRECTING, drop);
    a.copy(8, SAVED_CB, 9, layout.ctx_cb, 20);
    a.copy(9, layout.ctx_cb, 8, 8, 8);
    a.copy(9, layout.ctx_cb + 8, 8, 0, 8);
    a.emit(ST_W, 9, 0, layout.ctx_cb + 16, 0);
    phase_cas(
        &mut a,
        8,
        NATIVE_OP_REDIRECTING,
        NATIVE_OP_REDIRECT_REQUESTED,
        drop,
    );
    a.emit(LDX_W, 1, 8, 168, 0);
    a.emit(MOV_K, 2, 0, 0, 1);
    a.emit(CALL, 0, 0, 0, 23);
    a.emit(EXIT, 0, 0, 0, 0);
    a.bind(drop);
    a.exit(2);
    let mut program = static_finish(a)?;
    program.flags = 0;
    Ok(program)
}
fn association(a: &mut Asm, cb_base: u8, cb: i16, failure: Target) {
    for (scratch, operation) in [(0, 8), (4, 12), (8, 0), (12, 4)] {
        a.emit(LDX_W, 0, cb_base, cb + scratch, 0);
        a.emit(LDX_W, 1, 8, operation, 0);
        a.jump(JNE_X, 0, 1, 0, failure);
    }
    a.emit(LDX_W, 0, cb_base, cb + 16, 0);
    a.jump(JNE_K, 0, 0, 0, failure);
}
fn restorer(
    config: &CapturedProgramConfig<'_>,
    layout: &layout::CapturedLayout,
) -> io::Result<Program> {
    let mut a = Asm::new();
    let next = a.label();
    a.mov(9, 1);
    op(&mut a, config, next);
    a.emit(LDX_W, 0, 8, PHASE, 0);
    a.jump(JNE_K, 0, 0, NATIVE_OP_ENTERED as i32, next);
    a.emit(LDX_W, 0, 9, 36, 0);
    a.emit(LDX_W, 1, 8, 168, 0);
    a.jump(JNE_X, 0, 1, 0, next);
    association(&mut a, 9, layout.ctx_cb, next);
    a.copy(9, layout.ctx_cb, 8, SAVED_CB, 20);
    a.bind(next);
    a.exit(-1);
    let mut program = static_finish(a)?;
    program.flags = 0;
    Ok(program)
}
fn kernel_read(a: &mut Asm, source: u8, offset: i16, length: i32, dest: i16, failure: Target) {
    a.ptr(3, source, offset);
    a.ptr(1, 10, dest);
    a.emit(MOV_K, 2, 0, 0, length);
    a.emit(CALL, 0, 0, 0, 113);
    a.jump(JNE_K, 0, 0, 0, failure);
}
fn entry(
    config: &CapturedProgramConfig<'_>,
    layout: &layout::CapturedLayout,
) -> io::Result<Program> {
    if config.targets.len() > MAX_CAPTURED_TARGETS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "captured target count exceeds static instruction admission",
        ));
    }
    let mut a = Asm::new();
    let done = a.label();
    let valid = a.label();
    a.mov(9, 1);
    a.emit(LDX_DW, 6, 9, 0, 0);
    op(&mut a, config, done);
    a.emit(LDX_W, 0, 8, PHASE, 0);
    a.jump(JNE_K, 0, 0, NATIVE_OP_REDIRECT_REQUESTED as i32, done);
    kernel_read(&mut a, 6, layout.skb_dev, 8, ROOT, done);
    a.emit(LDX_DW, 7, 10, ROOT, 0);
    a.jump(JEQ_K, 7, 0, 0, done);
    kernel_read(&mut a, 7, layout.dev_ifindex, 4, INDEX, done);
    a.emit(LDX_W, 0, 10, INDEX, 0);
    a.emit(LDX_W, 1, 8, 168, 0);
    a.jump(JNE_X, 0, 1, 0, done);
    for target in config.targets {
        let other = a.label();
        a.jump(
            JNE32_K,
            0,
            0,
            target.target.capture.authority.ifindex as i32,
            other,
        );
        equals64(
            &mut a,
            8,
            16,
            target.target.capture.authority.attachment_generation,
            done,
        );
        a.go(valid);
        a.bind(other);
    }
    a.go(done);
    a.bind(valid);
    kernel_read(&mut a, 7, layout.dev_net, 8, ROOT, done);
    a.emit(LDX_DW, 7, 10, ROOT, 0);
    a.jump(JEQ_K, 7, 0, 0, done);
    kernel_read(&mut a, 7, layout.net_cookie, 8, ROOT, done);
    a.emit(LDX_DW, 0, 10, ROOT, 0);
    a.emit(LDX_DW, 1, 8, OP_KEY + 40, 0);
    a.jump(JNE_X, 0, 1, 0, done);
    kernel_read(
        &mut a,
        6,
        layout.skb_cb + layout.cb_data,
        20,
        ORIGINAL,
        done,
    );
    association(&mut a, 10, ORIGINAL, done);
    phase_cas(
        &mut a,
        8,
        NATIVE_OP_REDIRECT_REQUESTED,
        NATIVE_OP_ENTERING,
        done,
    );
    a.imm(0, 1);
    a.emit(STX_DW, 8, 0, ENTRY_SEQ, 0);
    a.emit(ST_W, 8, 0, RECEIPT, 1);
    phase_cas(&mut a, 8, NATIVE_OP_ENTERING, NATIVE_OP_ENTERED, done);
    a.bind(done);
    a.exit(0);
    let mut program = static_finish(a)?;
    program.flags = 0;
    Ok(program)
}

pub(in crate::bpf) fn prepare_gate(
    target: &NativeTarget,
    config: &NativeProgramConfig<'_>,
    captured: &CapturedProgramConfig<'_>,
    log: &mut [u8],
) -> io::Result<CanonicalGate> {
    let gate = gate_owner(target)?;
    let owner = gate
        .captured
        .lock()
        .map_err(|_| invalid_data("captured attachment lock poisoned"))?
        .clone()
        .ok_or_else(|| invalid_data("captured canonical staging has no static owner"))?;
    if captured.return_attachment != owner.return_attachment()
        || captured.tap_ifindex != owner.tap_ifindex()
        || object_id(captured.root)? != owner.root_map_id()
        || object_id(captured.operation)? != owner.operation_map_id()
        || object_id(unsafe { BorrowedFd::borrow_raw(config.root) })? != owner.root_map_id()
    {
        return Err(invalid_data(
            "captured canonical staging changes cell authority",
        ));
    }
    if captured.pin_root != owner.pin_root()
        || captured.targets.len() != owner.targets().len()
        || captured
            .targets
            .iter()
            .zip(owner.targets())
            .any(|(actual, expected)| {
                actual.realm_index != expected.realm_index
                    || actual.logical_ifindex != expected.logical_ifindex
                    || !Arc::ptr_eq(&actual.target, &expected.target)
            })
    {
        return Err(invalid_data(
            "captured canonical staging changes registered targets",
        ));
    }
    owner.check()?;
    let descriptor = owner
        .targets()
        .iter()
        .find(|item| std::ptr::eq(item.target.as_ref(), target))
        .ok_or_else(|| invalid_data("captured canonical target is unregistered"))?;
    let realm = descriptor.realm_index;
    let candidate = {
        let mut state = owner.state()?;
        if state
            .realms
            .iter()
            .filter(|gate| gate.realm == realm)
            .count()
            >= 2
        {
            return Err(capacity(
                "captured realm candidate overlap exceeds two generations",
            ));
        }
        let candidate = state
            .next_candidate
            .checked_add(1)
            .ok_or_else(|| capacity("captured candidate serial exhausted"))?;
        state.next_candidate = candidate;
        candidate
    };
    let basename = format!("realm-{realm}-gate-{}-{candidate}-prog", config.epoch);
    let program = canonical(config, captured, realm)?;
    let object = owner.intend(
        "realm-gate-prog",
        owner.0.path.join(&basename),
        BPF_PROG_TYPE_XDP,
        owner.0.tap,
    )?;
    let mut state = owner.state()?;
    state
        .realms
        .try_reserve(1)
        .map_err(|_| capacity("captured realm receipt allocation"))?;
    state.realms.push(RealmGate {
        realm,
        epoch: config.epoch,
        object,
        selected: false,
    });
    drop(state);
    let (fd, id) = load_program(&program, b"honk_ret_realm", log)?;
    let candidate = fd.try_clone()?;
    owner.observe(object, fd)?;
    owner.pin(
        object,
        owner.directory()?.as_fd(),
        &CString::new(basename).unwrap(),
    )?;
    let receipt = owner.state()?.objects[object].receipt.clone();
    Ok(CanonicalGate {
        program: candidate,
        owner,
        realm,
        epoch: config.epoch,
        id,
        object,
        receipt,
    })
}

impl CanonicalGate {
    pub(in crate::bpf) fn memory_bytes(&self) -> io::Result<u64> {
        let metadata = size_of::<Self>()
            .checked_add(self.receipt.pin_path.capacity())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| capacity("captured canonical receipt charge overflow"))?;
        fd_memlock(self.program.as_fd())?
            .checked_add(metadata)
            .ok_or_else(|| capacity("captured canonical resident charge overflow"))
    }

    pub(in crate::bpf) fn identity(&self) -> CapturedGateIdentity {
        let state = self
            .owner
            .0
            .installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let object = &state.objects[self.object];
        let mut resource = self.receipt.clone();
        resource.state = if object.receipt.id == self.id {
            object.receipt.state
        } else {
            CapturedResourceState::Unpinned
        };
        CapturedGateIdentity {
            resource,
            realm_index: self.realm,
            closed_epoch: self.epoch,
        }
    }
}

impl CanonicalGate {
    pub(in crate::bpf) fn publish(&self, target: &NativeTarget) -> io::Result<()> {
        if !self.owner.targets().iter().any(|item| {
            item.realm_index == self.realm && std::ptr::eq(item.target.as_ref(), target)
        }) {
            return Err(invalid_data(
                "captured realm candidate published to a foreign target",
            ));
        }
        let root: NativeRoot = map_value(self.owner.0.root.as_fd(), &0)?;
        if root.epoch != self.epoch || root.epoch & 1 != 0 || root.reserved != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "captured canonical publication requires its closed root",
            ));
        }
        let native = target
            .attachment
            .native
            .as_ref()
            .unwrap()
            .lock()
            .map_err(|_| invalid_data("Native attachment lock poisoned"))?;
        native.require_gate_with(NativeTcxAttachment::check)?;
        let mut state = self.owner.state()?;
        let dispatch = state
            .objects
            .iter()
            .find(|object| object.receipt.role == "realm-dispatch-map")
            .unwrap()
            .fd
            .as_ref()
            .unwrap();
        let dispatch = dispatch.try_clone()?;
        state.objects[self.object].intent = true;
        let fd = self.program.as_raw_fd() as u32;
        bpf(
            BPF_MAP_UPDATE_ELEM,
            &mut map_attr(dispatch.as_fd(), &self.realm, &fd as *const u32 as u64),
        )?;
        state.objects[self.object].installed = true;
        if map_value::<u32>(dispatch.as_fd(), &self.realm)? != self.id {
            return Err(invalid_data("captured canonical slot readback mismatch"));
        }
        for gate in state
            .realms
            .iter_mut()
            .filter(|gate| gate.realm == self.realm)
        {
            gate.selected = gate.object == self.object;
        }
        state.objects[self.object].intent = false;
        Ok(())
    }
}

pub(in crate::bpf) fn finish_publication(target: &NativeTarget) -> io::Result<()> {
    let gate = gate_owner(target)?;
    let owner = gate
        .captured
        .lock()
        .map_err(|_| invalid_data("captured attachment lock poisoned"))?
        .clone();
    let Some(owner) = owner else {
        return Ok(());
    };
    let mut state = owner.state()?;
    let retired: Vec<usize> = state
        .realms
        .iter()
        .filter(|gate| !gate.selected)
        .map(|gate| gate.object)
        .collect();
    for index in retired {
        let object = &mut state.objects[index];
        if object.intent {
            return Err(invalid_data("captured canonical replacement is unresolved"));
        }
        if object.pinned {
            let name = CString::new(
                object
                    .receipt
                    .pin_path
                    .file_name()
                    .unwrap()
                    .as_encoded_bytes(),
            )
            .unwrap();
            verify_pin(owner.directory()?.as_fd(), &name, object.receipt.id)?;
            object.intent = true;
            if unsafe { libc::unlinkat(owner.directory()?.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            object.pinned = false;
            object.intent = false;
            object.receipt.state = CapturedResourceState::Unpinned;
        }
        object.fd.take();
        object.memlock = 0;
    }
    state.realms.retain(|gate| gate.selected);
    Ok(())
}

fn canonical(
    config: &NativeProgramConfig<'_>,
    captured: &CapturedProgramConfig<'_>,
    realm: u32,
) -> io::Result<Program> {
    let mut a = Asm::new();
    a.b.reserve(
        config
            .bytecode
            .len()
            .checked_add(STATIC_LIMIT)
            .ok_or_else(|| capacity("captured canonical instruction overflow"))?,
    )?;
    let drop = a.label();
    let refuse = a.label();
    let unlock = a.label();
    let chosen = a.label();
    a.mov(9, 1);
    a.zero(10, ACTIVITY_NOW, -ACTIVITY_NOW as usize);
    op(&mut a, captured, drop);
    a.emit(STX_DW, 10, 8, OP_PTR, 0);
    a.emit(LDX_W, 0, 8, PHASE, 0);
    a.jump(JNE_K, 0, 0, NATIVE_OP_ADMITTING as i32, drop);
    a.emit(LDX_W, 0, 8, 176, 0);
    a.jump(JNE32_K, 0, 0, realm as i32, refuse);
    a.emit(LDX_W, 0, 9, 12, 0);
    a.jump(JNE32_K, 0, 0, captured.tap_ifindex as i32, refuse);
    a.emit(LDX_DW, 0, 8, 24, 0);
    a.jump(JEQ_K, 0, 0, 0, refuse);
    a.mov(1, 0);
    a.emit(AND_K, 1, 0, 0, 1);
    a.jump(JEQ_K, 1, 0, 0, refuse);
    a.emit(LDX_DW, 1, 8, 32, 0);
    a.jump(JNE_X, 0, 1, 0, refuse);
    a.emit(LDX_DW, 0, 8, 48, 0);
    a.jump(JEQ_K, 0, 0, 0, refuse);
    a.emit(AND_K, 0, 0, 0, 1);
    a.jump(JEQ_K, 0, 0, 0, refuse);
    equals64(&mut a, 8, 40, config.scope, refuse);
    for off in [200, 204, 208, 236, 240, 244, 252, 256, 260] {
        a.emit(LDX_W, 0, 8, off, 0);
        a.jump(JNE_K, 0, 0, 0, refuse);
    }
    a.emit(LDX_W, 0, 8, 212, 0);
    a.emit(AND_K, 0, 0, 0, !63);
    a.jump(JNE_K, 0, 0, 0, refuse);
    a.emit(LDX_W, 0, 8, 196, 0);
    a.jump(JNE_K, 0, 0, 1, refuse);
    a.emit(LDX_W, 0, 8, 184, 0);
    a.jump(JNE_K, 0, 0, 14, refuse);
    envelope(&mut a, false, refuse);
    a.emit(LDX_DW, 7, 10, OP_PTR, 0);
    a.emit(LDX_W, 0, 10, FRAME_LEN, 0);
    a.emit(LDX_W, 1, 7, 180, 0);
    a.jump(JNE_X, 0, 1, 0, refuse);
    a.emit(LDX_W, 0, 10, DSCP, 0);
    a.emit(LDX_B, 1, 7, 212, 0);
    a.jump(JNE_X, 0, 1, 0, refuse);
    a.emit(LDX_W, 6, 9, 0, 0);
    // The reloaded packet pointer has no verified range; both L3 length reads end within 20 bytes.
    a.emit(LDX_W, 1, 9, 4, 0);
    a.mov(0, 6);
    a.emit(ADD_K, 0, 0, 0, 20);
    a.jump(JGT_X, 0, 1, 0, refuse);
    let ipv6_extent = a.label();
    let extent_ready = a.label();
    a.emit(LDX_B, 0, 10, KEY + 37, 0);
    a.jump(JEQ_K, 0, 0, 6, ipv6_extent);
    a.emit(LDX_H, 0, 6, 16, 0);
    a.emit(BE16, 0, 0, 0, 16);
    a.go(extent_ready);
    a.bind(ipv6_extent);
    a.emit(LDX_H, 0, 6, 18, 0);
    a.emit(BE16, 0, 0, 0, 16);
    a.emit(ADD_K, 0, 0, 0, 40);
    a.bind(extent_ready);
    a.emit(LDX_W, 1, 7, 188, 0);
    a.jump(JNE_X, 0, 1, 0, refuse);
    a.emit(LDX_W, 0, 7, 168, 0);
    a.emit(STX_W, 10, 0, FRAME_LEN, 0);
    for target in captured
        .targets
        .iter()
        .filter(|target| target.realm_index == realm)
    {
        let other = a.label();
        let authority = target.target.capture.authority;
        a.emit(LDX_W, 0, 10, FRAME_LEN, 0);
        a.jump(JNE32_K, 0, 0, authority.ifindex as i32, other);
        equals64(&mut a, 7, 16, authority.attachment_generation, refuse);
        equals64(&mut a, 7, OP_KEY + 40, authority.namespace_cookie, refuse);
        a.emit(LDX_W, 0, 7, 172, 0);
        a.jump(JNE32_K, 0, 0, target.logical_ifindex as i32, refuse);
        a.emit(LDX_W, 0, 7, 248, 0);
        a.jump(JGE_K, 0, 0, target.target.queues as i32, refuse);
        a.emit(STX_W, 10, 0, INDEX, 0);
        a.lookup(target.target.xsks.as_raw_fd(), INDEX);
        a.jump(JEQ_K, 0, 0, 0, refuse);
        a.imm(0, authority.namespace_cookie);
        a.emit(STX_DW, 10, 0, KEY + 40, 0);
        a.emit(ST_W, 10, 0, KEY + 48, 2 << 16);
        a.emit(ST_W, 10, 0, KEY + 52, 0);
        a.go(chosen);
        a.bind(other);
    }
    a.go(refuse);
    a.bind(chosen);
    for off in (0..56).step_by(4) {
        a.emit(LDX_W, 0, 10, KEY + off, 0);
        a.emit(LDX_W, 1, 7, OP_KEY + off, 0);
        a.jump(JNE_X, 0, 1, 0, refuse);
    }
    a.b.map_fd(config.claims);
    a.ptr(2, 7, OP_KEY);
    a.emit(CALL, 0, 0, 0, 1);
    a.jump(JEQ_K, 0, 0, 0, refuse);
    a.emit(STX_DW, 10, 0, CLAIM_PTR, 0);
    a.mov(6, 0);
    for (claim, operation) in [(0, 24), (8, 32), (16, 40)] {
        a.emit(LDX_DW, 0, 6, claim, 0);
        a.emit(LDX_DW, 1, 7, operation, 0);
        a.jump(JNE_X, 0, 1, 0, refuse);
    }
    a.emit(LDX_DW, 0, 6, 0, 0);
    a.jump(JEQ_K, 0, 0, 0, refuse);
    a.emit(LDX_DW, 1, 6, 8, 0);
    a.jump(JNE_X, 0, 1, 0, refuse);
    a.emit(AND_K, 0, 0, 0, 1);
    a.jump(JEQ_K, 0, 0, 0, refuse);
    for off in (40..72).step_by(4) {
        a.emit(LDX_W, 0, 6, off, 0);
        a.jump(JNE_K, 0, 0, 0, refuse);
    }
    a.emit(CALL, 0, 0, 0, 8);
    a.emit(STX_W, 10, 0, INDEX, 0);
    a.lookup(config.scratch, INDEX);
    a.jump(JEQ_K, 0, 0, 0, refuse);
    a.mov(8, 0);
    a.emit(MOV_K, 0, 0, 0, 0);
    a.emit(MOV_K, 1, 0, 0, 1);
    a.emit(CMPXCHG_W, 8, 1, SCRATCH_BUSY, CMPXCHG_DW);
    a.jump(JNE_K, 0, 0, 0, refuse);
    a.zero(
        8,
        SCRATCH_INPUT,
        size_of::<RoutingInput>() + size_of::<KernelRouteOutput>(),
    );
    a.copy(8, SCRATCH_INPUT, 7, OP_KEY, 32);
    for (source, dest) in [
        (32, std::mem::offset_of!(RoutingInput, src_port)),
        (34, std::mem::offset_of!(RoutingInput, dst_port)),
    ] {
        a.emit(LDX_H, 0, 7, OP_KEY + source, 0);
        a.emit(BE16, 0, 0, 0, 16);
        a.emit(STX_W, 8, 0, SCRATCH_INPUT + dest as i16, 0);
    }
    input_protocol(&mut a, 7, OP_KEY);
    a.emit(LDX_B, 0, 7, 212, 0);
    a.emit(
        STX_W,
        8,
        0,
        SCRATCH_INPUT + std::mem::offset_of!(RoutingInput, dscp) as i16,
        0,
    );
    a.emit(ST_W, 10, 0, INDEX, 0);
    a.lookup(config.root, INDEX);
    a.jump(JEQ_K, 0, 0, 0, unlock);
    a.emit(STX_DW, 10, 0, ROOT, 0);
    a.mov(6, 0);
    a.emit(LDX_W, 0, 6, 12, 0);
    a.jump(JNE_K, 0, 0, 0, unlock);
    a.emit(LDX_DW, 0, 6, 0, 0);
    a.emit(LDX_DW, 1, 7, 56, 0);
    a.jump(JNE_X, 0, 1, 0, unlock);
    a.jump(JEQ_K, 0, 0, 0, unlock);
    a.emit(AND_K, 0, 0, 0, 1);
    a.jump(JEQ_K, 0, 0, 0, unlock);
    a.emit(LDX_W, 0, 6, 8, 0);
    a.emit(STX_W, 10, 0, FLAGS, 0);
    let global = a.label();
    a.jump(
        JSET_K,
        0,
        0,
        DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as i32,
        global,
    );
    let call = a.label();
    a.go(call);
    a.bind(global);
    a.emit(
        ST_W,
        8,
        0,
        SCRATCH_INPUT + std::mem::offset_of!(RoutingInput, flags) as i16,
        ROUTING_INPUT_ALLOW_DIRECT_FINALITY as i32,
    );
    a.bind(call);
    a.ptr(1, 8, SCRATCH_INPUT);
    a.ptr(2, 8, SCRATCH_OUTPUT);
    let canonical_call = a.emit(CALL, 0, 1, 0, 0);
    a.jump(JNE_K, 0, 0, 0, unlock);
    a.emit(LDX_W, 0, 8, OUTBOUND, 0);
    a.jump(JNE_K, 0, 0, 0, unlock);
    let finality = a.label();
    route(&mut a, config.reply_block_rules, finality, unlock, unlock);
    a.bind(finality);
    let live = a.label();
    for target in captured
        .targets
        .iter()
        .filter(|target| target.realm_index == realm)
    {
        let other = a.label();
        a.emit(LDX_W, 0, 7, 168, 0);
        a.jump(
            JNE32_K,
            0,
            0,
            target.target.capture.authority.ifindex as i32,
            other,
        );
        a.emit(LDX_W, 0, 7, 248, 0);
        a.emit(STX_W, 10, 0, INDEX, 0);
        a.lookup(target.target.xsks.as_raw_fd(), INDEX);
        a.jump(JEQ_K, 0, 0, 0, unlock);
        a.go(live);
        a.bind(other);
    }
    a.go(unlock);
    a.bind(live);
    a.emit(LDX_DW, 6, 10, CLAIM_PTR, 0);
    a.emit(LDX_DW, 0, 6, 24, 0);
    a.mov(2, 0);
    a.emit(RSH_K, 2, 0, 0, 32);
    a.mov(3, 2);
    a.emit(RSH_K, 3, 0, 0, 4);
    a.jump(JEQ_K, 3, 0, 0, unlock);
    a.jump(JGT_K, 3, 0, config.redirect_limit as i32, unlock);
    a.emit(AND_K, 2, 0, 0, 15);
    a.mov(4, 0);
    a.emit(0xbc, 4, 0, 0, 0);
    let follower = a.label();
    let selected = a.label();
    a.jump(JEQ_K, 4, 0, 2, follower);
    a.jump(JNE_K, 4, 0, 3, unlock);
    a.jump(JNE_K, 2, 0, 0, unlock);
    // The phase occupies bits32..35; preserve all 28 outstanding bits above it.
    a.mov(1, 0);
    a.imm(2, 0xfffffff000000000);
    a.emit(0x5f, 1, 2, 0, 0);
    a.imm(2, 0x0000000200000002);
    a.emit(0x4f, 1, 2, 0, 0);
    a.mov(4, 0);
    a.emit(ATOMIC_ADD_DW, 6, 1, 24, CMPXCHG_DW);
    a.jump(JNE_X, 0, 4, 0, unlock);
    a.go(selected);
    a.bind(follower);
    a.jump(JEQ_K, 2, 0, 2, selected);
    a.jump(JNE_K, 2, 0, 3, unlock);
    a.bind(selected);
    a.emit(LDX_DW, 6, 10, ROOT, 0);
    a.emit(LDX_DW, 0, 7, 56, 0);
    a.mov(1, 0);
    a.emit(ATOMIC_ADD_DW, 6, 1, 0, CMPXCHG_DW);
    a.jump(JNE_X, 0, 1, 0, unlock);
    a.emit(CALL, 0, 0, 0, 125);
    a.emit(LDX_DW, 1, 7, 64, 0);
    a.jump(JGE_X, 0, 1, 0, unlock);
    a.imm(1, config.expires_boottime_ns);
    a.jump(JGE_X, 0, 1, 0, unlock);
    a.emit(ST_W, 8, 0, SCRATCH_BUSY, 0);
    phase_cas(&mut a, 7, NATIVE_OP_ADMITTING, NATIVE_OP_ADMITTED, drop);
    a.exit(XDP_PASS);
    a.bind(unlock);
    a.emit(ST_W, 8, 0, SCRATCH_BUSY, 0);
    a.bind(refuse);
    a.emit(LDX_DW, 8, 10, OP_PTR, 0);
    phase_cas(&mut a, 8, NATIVE_OP_ADMITTING, NATIVE_OP_GATE_REFUSED, drop);
    a.bind(drop);
    a.exit(XDP_DROP);
    if a.b.program.len > STATIC_LIMIT {
        return Err(capacity("captured canonical wrapper exceeds charged bound"));
    }
    let body = a.b.program.len;
    a.b.program.insns[canonical_call].imm = (body as isize - canonical_call as isize - 1) as i32;
    for insn in config.bytecode {
        a.emit(
            insn.code,
            insn.dst_reg(),
            insn.src_reg(),
            insn.off,
            insn.imm,
        );
    }
    let mut program = a.finish()?;
    program.flags |= 1 << 5;
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::xdp::*;

    const CELL: usize = 0x2100;
    const ROOT_CELL: usize = 0x2400;
    const CLAIM_CELL: usize = 0x2500;
    const SCRATCH_CELL: usize = 0x3000;
    const CONTEXT: usize = 0x5000;
    const PACKET: usize = 0x6000;
    const SKB: usize = 0x7000;
    const DEV: usize = 0x7100;
    const NET: usize = 0x7200;

    fn word(memory: &mut [u8], at: usize, value: u64, width: usize) {
        memory[at..at + width].copy_from_slice(&value.to_ne_bytes()[..width]);
    }
    fn value<T: Copy>(memory: &mut [u8], at: usize, value: &T) {
        // The fixtures use only the shared, padding-free wire structs.
        let bytes =
            unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) };
        memory[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn get(memory: &[u8], at: usize, width: usize) -> u64 {
        let mut bytes = [0; 8];
        bytes[..width].copy_from_slice(&memory[at..at + width]);
        u64::from_ne_bytes(bytes)
    }
    fn fd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }

    #[test]
    fn trace_close_requires_absent_link_and_program_and_retains_kernel_errno() {
        let absent = || Err(io::Error::from_raw_os_error(libc::ENOENT));
        assert!(tracing_release_complete(absent(), absent()).unwrap());
        assert!(!tracing_release_complete(Ok(fd()), absent()).unwrap());
        assert!(!tracing_release_complete(absent(), Ok(fd())).unwrap());
        assert!(!tracing_release_complete(Ok(fd()), Ok(fd())).unwrap());
        for program in [false, true] {
            let failure = || Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            let error = if program {
                tracing_release_complete(absent(), failure())
            } else {
                tracing_release_complete(failure(), absent())
            }
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(error.to_string().contains(if program {
                "captured close: entry tracing program ID release proof"
            } else {
                "captured close: entry tracing link ID release proof"
            }));
            let cause = error
                .get_ref()
                .unwrap()
                .downcast_ref::<CapturedStepError>()
                .unwrap();
            assert_eq!(cause.source.raw_os_error(), Some(libc::EOPNOTSUPP));
            assert!(error.to_string().contains(&cause.source.to_string()));
        }
    }
    #[cfg(feature = "captured-fault")]
    #[test]
    fn missing_entry_readback_rejects_aggregate_and_extra_context() {
        let missing = || {
            captured_context("close: seal readback")(captured_context(MISSING_ENTRY_CHECK_STEP)(
                io::ErrorKind::InvalidData.into(),
            ))
        };
        assert!(CapturedPrograms::is_missing_entry_readback_error_for_test(
            &missing()
        ));
        let aggregate =
            combine_observation::<()>(Err(missing()), Err(io::Error::other("observer")))
                .unwrap_err();
        assert!(!CapturedPrograms::is_missing_entry_readback_error_for_test(
            &aggregate
        ));
        let contextual = captured_context("additional Core folding context")(missing());
        assert!(!CapturedPrograms::is_missing_entry_readback_error_for_test(
            &contextual
        ));
        let wrong_step =
            captured_context("close: seal readback")(captured_context("check: verify owned pin")(
                invalid_data("captured active entry witness incomplete"),
            ));
        assert!(!CapturedPrograms::is_missing_entry_readback_error_for_test(
            &wrong_step
        ));
    }

    struct Fixture {
        root: OwnedFd,
        operation: OwnedFd,
        targets: Vec<CapturedTarget>,
        packet: Vec<u8>,
        output: KernelRouteOutput,
    }
    impl Fixture {
        fn new() -> Self {
            let target = Arc::new(NativeTarget {
                counters: fd(),
                xsks: fd(),
                dispatch: fd(),
                query_program: Arc::new(Mutex::new(None)),
                capture: GeneralCapture {
                    authority: CaptureAuthority {
                        namespace_cookie: 7,
                        attachment_generation: 17,
                        scope: 11,
                        config_generation: 4,
                        ifindex: 2,
                        reserved: 0,
                    },
                    bypass_mark: 128,
                    vlan_metadata: false,
                },
                broadcasts: Vec::new(),
                queues: 2,
                vlan_kfunc: None,
                attachment: PersistentAttachment {
                    ifindex: 2,
                    discover_id: 1,
                    data_id: 2,
                    native: None,
                },
                recording: Mutex::new(None),
            });
            let mut packet = vec![0; 42];
            packet[0] = 2;
            packet[6] = 2;
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            packet[14] = 0x45;
            packet[16..18].copy_from_slice(&28u16.to_be_bytes());
            packet[22] = 64;
            packet[23] = 17;
            packet[26..30].copy_from_slice(&[192, 0, 2, 1]);
            packet[30..34].copy_from_slice(&[198, 51, 100, 2]);
            packet[34..36].copy_from_slice(&12345u16.to_be_bytes());
            packet[36..38].copy_from_slice(&443u16.to_be_bytes());
            packet[38..40].copy_from_slice(&8u16.to_be_bytes());
            Self {
                root: fd(),
                operation: fd(),
                targets: vec![CapturedTarget {
                    realm_index: 0,
                    logical_ifindex: 2,
                    target,
                }],
                packet,
                output: KernelRouteOutput {
                    decision: RoutingDecision {
                        outbound: 0,
                        ..RoutingDecision::default()
                    },
                    ..KernelRouteOutput::default()
                },
            }
        }
        fn config(&self) -> CapturedProgramConfig<'_> {
            CapturedProgramConfig {
                root: self.root.as_fd(),
                operation: self.operation.as_fd(),
                return_attachment: 13,
                tap_ifindex: 23,
                targets: &self.targets,
                pin_root: Path::new("/private"),
            }
        }
        fn native(&self) -> NativeProgramConfig<'_> {
            NativeProgramConfig {
                bytecode: &[],
                root: self.root.as_raw_fd(),
                claims: 101,
                scratch: 102,
                closed_counters: 103,
                hook_ids: [1, 2],
                epoch: 4,
                scope: 11,
                expires_boottime_ns: 99,
                redirect_limit: 16,
                captured: None,
                reply_block_rules: &[],
                preparation_memory_bytes: 0,
            }
        }
        fn memory(&self) -> Vec<u8> {
            let key = NativeKey {
                src_ip: [
                    0,
                    0,
                    u32::from_ne_bytes([0, 0, 255, 255]),
                    u32::from_ne_bytes([192, 0, 2, 1]),
                ],
                dst_ip: [
                    0,
                    0,
                    u32::from_ne_bytes([0, 0, 255, 255]),
                    u32::from_ne_bytes([198, 51, 100, 2]),
                ],
                src_port: 12345u16.to_be(),
                dst_port: 443u16.to_be(),
                l4proto: 17,
                ip_version: 4,
                namespace_cookie: 7,
                zone_state: NATIVE_ZONE_TRANSIT_DEFAULT,
                ..NativeKey::default()
            };
            let operation = NativeCapturedOperation {
                op_incarnation: 4,
                return_attachment: 13,
                ingress_attachment: 17,
                claim_epoch: 3,
                claim_incarnation: 3,
                claim_scope: 11,
                capture_epoch: 3,
                basis_epoch: 5,
                expires_boottime_ns: 99,
                key,
                ingress_ifindex: 2,
                logical_ifindex: 2,
                frame_length: 42,
                l3_offset: 14,
                l3_length: 28,
                phase: NATIVE_OP_ADMITTING,
                flags: NATIVE_IMPORT_COUNTED,
                ..NativeCapturedOperation::default()
            };
            let claim = NativeClaim {
                epoch: 3,
                incarnation: 3,
                scope: 11,
                executor: NATIVE_EXECUTOR_PENDING,
                state: 2 << 4,
                ..NativeClaim::default()
            };
            let mut memory = vec![0; 0x8000];
            memory[0] = 1;
            memory[1] = 1;
            value(&mut memory, CELL, &operation);
            value(&mut memory, CLAIM_CELL, &claim);
            value(
                &mut memory,
                ROOT_CELL,
                &NativeRoot {
                    epoch: 5,
                    flags: DATAPATH_FLAG_OFFLOAD_RULE_DIRECT,
                    reserved: 0,
                },
            );
            word(&mut memory, CONTEXT, PACKET as u64, 4);
            word(
                &mut memory,
                CONTEXT + 4,
                (PACKET + self.packet.len()) as u64,
                4,
            );
            word(&mut memory, CONTEXT + 12, 23, 4);
            word(&mut memory, CONTEXT + 36, 23, 4);
            memory[PACKET..PACKET + self.packet.len()].copy_from_slice(&self.packet);
            word(&mut memory, SKB, DEV as u64, 8);
            word(&mut memory, DEV, 2, 4);
            word(&mut memory, DEV + 8, NET as u64, 8);
            word(&mut memory, NET, 7, 8);
            memory
        }
        fn run(&self, program: &Program, memory: &mut [u8], close_after_canonical: bool) -> u64 {
            let mut regs = [0; 11];
            regs[1] = CONTEXT as u64;
            regs[10] = 0x1200;
            super::super::tests::execute(program, memory, &mut regs, |instruction, regs, memory| {
                let dst = (instruction.regs & 15) as usize;
                let src = (instruction.regs >> 4) as usize;
                match instruction.code {
                    0xbc => {
                        regs[dst] = u64::from(regs[src] as u32);
                        true
                    }
                    0x5f => {
                        regs[dst] &= regs[src];
                        true
                    }
                    0x4f => {
                        regs[dst] |= regs[src];
                        true
                    }
                    CALL if src == 1 => {
                        value(memory, SCRATCH_CELL + SCRATCH_OUTPUT as usize, &self.output);
                        let finality = u64::from(memory[0]);
                        word(memory, SCRATCH_CELL + FINAL as usize, finality, 4);
                        if close_after_canonical {
                            word(memory, ROOT_CELL, 6, 8);
                        }
                        if memory[2] == 1 {
                            memory[1] = 0;
                        }
                        regs[0] = 0;
                        true
                    }
                    CALL => {
                        regs[0] = match instruction.imm {
                            1 if regs[1] == self.operation.as_raw_fd() as u64 => CELL as u64,
                            1 if regs[1] == self.root.as_raw_fd() as u64 => ROOT_CELL as u64,
                            1 if regs[1] == 101 => CLAIM_CELL as u64,
                            1 if regs[1] == 102 => SCRATCH_CELL as u64,
                            1 if regs[1] == self.targets[0].target.xsks.as_raw_fd() as u64 => {
                                if memory[1] == 1 {
                                    0x4100
                                } else {
                                    0
                                }
                            }
                            8 | 12 => 0,
                            23 => 7,
                            125 => 50,
                            188 => self.packet.len() as u64,
                            113 => {
                                let bytes = memory
                                    [regs[3] as usize..regs[3] as usize + regs[2] as usize]
                                    .to_vec();
                                memory[regs[1] as usize..regs[1] as usize + bytes.len()]
                                    .copy_from_slice(&bytes);
                                0
                            }
                            other => panic!("unexpected captured helper {other}"),
                        };
                        true
                    }
                    _ => false,
                }
            })
        }
    }
    fn layout() -> layout::CapturedLayout {
        layout::CapturedLayout {
            entry: 1,
            skb_dev: 0,
            skb_cb: 32,
            cb_data: 8,
            ctx_cb: 48,
            dev_ifindex: 0,
            dev_net: 8,
            net_cookie: 0,
            cold_bytes: 0,
            tcx_link_bytes: 1,
            trace_link_bytes: 1,
        }
    }

    #[test]
    fn captured_gate_rejects_reserved_flags_and_projection() {
        let fixture = Fixture::new();
        let program = canonical(&fixture.native(), &fixture.config(), 0).unwrap();
        assert_eq!(
            fixture.run(&program, &mut fixture.memory(), false),
            XDP_PASS as u64
        );
        for offset in [
            213, 214, 215, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263,
        ] {
            let mut memory = fixture.memory();
            memory[CELL + offset] = 1;
            assert_eq!(
                fixture.run(&program, &mut memory, false),
                XDP_DROP as u64,
                "reserved byte {offset}"
            );
            assert_eq!(
                get(&memory, CELL + PHASE as usize, 4),
                u64::from(NATIVE_OP_GATE_REFUSED)
            );
        }
        for flags in [0, 2, 3, u32::MAX] {
            let mut memory = fixture.memory();
            word(&mut memory, CELL + 196, u64::from(flags), 4);
            assert_eq!(
                fixture.run(&program, &mut memory, false),
                XDP_DROP as u64,
                "flags {flags}"
            );
        }
        for offset in [
            OP_KEY + 38,
            OP_KEY + 39,
            OP_KEY + 40,
            OP_KEY + 48,
            OP_KEY + 50,
            OP_KEY + 51,
            OP_KEY + 52,
            OP_KEY + 53,
            OP_KEY + 54,
            OP_KEY + 55,
            16,
            168,
            172,
            176,
            180,
            184,
            188,
            200,
            204,
            208,
        ] {
            let mut memory = fixture.memory();
            memory[CELL + offset as usize] ^= 1;
            assert_eq!(
                fixture.run(&program, &mut memory, false),
                XDP_DROP as u64,
                "projection {offset}"
            );
        }
        let mut queue = fixture.memory();
        word(&mut queue, CELL + 248, 2, 4);
        assert_eq!(fixture.run(&program, &mut queue, false), XDP_DROP as u64);
        for offset in [40, 48, 56, 64, 68] {
            let mut memory = fixture.memory();
            memory[CLAIM_CELL + offset] = 1;
            assert_eq!(
                fixture.run(&program, &mut memory, false),
                XDP_DROP as u64,
                "Host owner/mark {offset}"
            );
        }
    }

    #[test]
    fn captured_gate_refuses_set_zero_full_width_and_unknown_effects() {
        let mut fixture = Fixture::new();
        let program = canonical(&fixture.native(), &fixture.config(), 0).unwrap();
        for (kind, mark) in [
            (honk_ebpf_common::ROUTING_MARK_SET, 0),
            (honk_ebpf_common::ROUTING_MARK_SET, 9),
            (honk_ebpf_common::ROUTING_MARK_SET, 0x8000_0000),
            (honk_ebpf_common::ROUTING_MARK_SET, u32::MAX),
            (2, 0),
            (ROUTING_MARK_KEEP, 9),
        ] {
            fixture.output.mark_kind = kind;
            fixture.output.decision.mark = mark;
            let mut memory = fixture.memory();
            let selection = get(&memory, CLAIM_CELL + 24, 8);
            assert_eq!(fixture.run(&program, &mut memory, false), XDP_DROP as u64);
            assert_eq!(get(&memory, CLAIM_CELL + 24, 8), selection);
            assert_eq!(get(&memory, SCRATCH_CELL + SCRATCH_BUSY as usize, 4), 0,);
            assert_eq!(
                get(&memory, CELL + PHASE as usize, 4),
                u64::from(NATIVE_OP_GATE_REFUSED),
            );
        }
    }

    #[test]
    fn captured_gate_final_frontier_and_selection_are_atomic() {
        let fixture = Fixture::new();
        let program = canonical(&fixture.native(), &fixture.config(), 0).unwrap();
        let mut memory = fixture.memory();
        assert_eq!(fixture.run(&program, &mut memory, false), XDP_PASS as u64);
        assert_eq!(
            get(&memory, CLAIM_CELL + 24, 8),
            native_selection(NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ARMED, 2).unwrap()
        );
        assert_eq!(
            get(&memory, CELL + PHASE as usize, 4),
            u64::from(NATIVE_OP_ADMITTED)
        );
        for phase in [NATIVE_PHASE_ARMED, NATIVE_PHASE_DRAINING] {
            let mut memory = fixture.memory();
            let selection = native_selection(NATIVE_EXECUTOR_KERNEL, phase, 2).unwrap();
            word(&mut memory, CLAIM_CELL + 24, selection, 8);
            assert_eq!(fixture.run(&program, &mut memory, false), XDP_PASS as u64);
            assert_eq!(get(&memory, CLAIM_CELL + 24, 8), selection);
        }
        for selection in [
            native_selection(NATIVE_EXECUTOR_CAPTURE, NATIVE_PHASE_CAPTURE_COMMITTED, 2).unwrap(),
            native_selection(NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ACTIVE, 0).unwrap(),
            native_selection(NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_SOURCE_PENDING, 2).unwrap(),
            native_selection(NATIVE_EXECUTOR_PENDING, NATIVE_PHASE_PENDING, 17).unwrap(),
        ] {
            let mut memory = fixture.memory();
            word(&mut memory, CLAIM_CELL + 24, selection, 8);
            assert_eq!(fixture.run(&program, &mut memory, false), XDP_DROP as u64);
            assert_eq!(get(&memory, CLAIM_CELL + 24, 8), selection);
        }
        for mutation in 0..4 {
            let mut memory = fixture.memory();
            match mutation {
                0 => memory[0] = 0,
                1 => memory[1] = 0,
                2 => word(&mut memory, CELL + 64, 50, 8),
                _ => word(&mut memory, ROOT_CELL, 7, 8),
            }
            assert_eq!(
                fixture.run(&program, &mut memory, false),
                XDP_DROP as u64,
                "frontier {mutation}"
            );
        }
        let mut stale_xsk = fixture.memory();
        stale_xsk[2] = 1;
        assert_eq!(
            fixture.run(&program, &mut stale_xsk, false),
            XDP_DROP as u64
        );
        let mut expired = fixture.native();
        expired.expires_boottime_ns = 50;
        let expired_program = canonical(&expired, &fixture.config(), 0).unwrap();
        assert_eq!(
            fixture.run(&expired_program, &mut fixture.memory(), false),
            XDP_DROP as u64
        );
        let mut memory = fixture.memory();
        assert_eq!(fixture.run(&program, &mut memory, true), XDP_DROP as u64);
        assert_eq!(
            get(&memory, CELL + PHASE as usize, 4),
            u64::from(NATIVE_OP_GATE_REFUSED)
        );
        assert_eq!(
            get(&memory, CLAIM_CELL + 24, 8),
            native_selection(NATIVE_EXECUTOR_KERNEL, NATIVE_PHASE_ARMED, 2).unwrap()
        );
    }

    #[test]
    fn captured_static_hooks_preserve_cb_and_publish_entry_once() {
        let fixture = Fixture::new();
        let config = fixture.config();
        let layout = layout();
        let redirect = redirector(&config, &layout).unwrap();
        let enter = entry(&config, &layout).unwrap();
        let restore = restorer(&config, &layout).unwrap();
        let dispatch = dispatcher(&config, 104).unwrap();
        for program in [&redirect, &enter, &restore, &dispatch] {
            assert!(program.len <= STATIC_LIMIT);
        }
        let mut memory = fixture.memory();
        word(
            &mut memory,
            CELL + PHASE as usize,
            u64::from(NATIVE_OP_ADMITTED),
            4,
        );
        let saved = [0xa5; 20];
        memory[CONTEXT + 48..CONTEXT + 68].copy_from_slice(&saved);
        assert_eq!(fixture.run(&redirect, &mut memory, false), 7);
        assert_eq!(
            &memory[CELL + SAVED_CB as usize..CELL + SAVED_CB as usize + 20],
            &saved
        );
        assert_eq!(
            get(&memory, CELL + PHASE as usize, 4),
            u64::from(NATIVE_OP_REDIRECT_REQUESTED)
        );
        let cb = memory[CONTEXT + 48..CONTEXT + 68].to_vec();
        memory[SKB + 40..SKB + 60].copy_from_slice(&cb);
        word(&mut memory, CONTEXT, SKB as u64, 8);
        assert_eq!(fixture.run(&enter, &mut memory, false), 0);
        assert_eq!(
            get(&memory, CELL + PHASE as usize, 4),
            u64::from(NATIVE_OP_ENTERED)
        );
        assert_eq!(get(&memory, CELL + RECEIPT as usize, 4), 1);
        assert_eq!(get(&memory, CELL + ENTRY_SEQ as usize, 8), 1);
        let receipt = memory[CELL..CELL + size_of::<NativeCapturedOperation>()].to_vec();
        fixture.run(&enter, &mut memory, false);
        assert_eq!(&memory[CELL..CELL + receipt.len()], receipt.as_slice());
        word(&mut memory, CONTEXT + 36, 2, 4);
        assert_eq!(fixture.run(&restore, &mut memory, false), u64::MAX);
        assert_eq!(&memory[CONTEXT + 48..CONTEXT + 68], &saved);
        memory[CONTEXT + 48..CONTEXT + 68].copy_from_slice(&cb);
        memory[CONTEXT + 48] ^= 1;
        let changed = memory[CONTEXT + 48..CONTEXT + 68].to_vec();
        fixture.run(&restore, &mut memory, false);
        assert_eq!(&memory[CONTEXT + 48..CONTEXT + 68], changed.as_slice());
        word(&mut memory, CONTEXT + 12, 23, 4);
        fixture.run(&dispatch, &mut memory, false);
        assert_eq!(&memory[CELL..CELL + receipt.len()], receipt.as_slice());
        let mut missing = fixture.memory();
        word(
            &mut missing,
            CELL + PHASE as usize,
            u64::from(NATIVE_OP_REDIRECT_REQUESTED),
            4,
        );
        word(&mut missing, CONTEXT, SKB as u64, 8);
        missing[SKB + 40..SKB + 60].copy_from_slice(&cb);
        missing[SKB + 56] = 1;
        fixture.run(&enter, &mut missing, false);
        assert_eq!(
            get(&missing, CELL + PHASE as usize, 4),
            u64::from(NATIVE_OP_REDIRECT_REQUESTED)
        );
        assert_eq!(get(&missing, CELL + RECEIPT as usize, 4), 0);
        for mutation in 0..4 {
            let mut late = fixture.memory();
            word(
                &mut late,
                CELL + PHASE as usize,
                u64::from(NATIVE_OP_REDIRECT_REQUESTED),
                4,
            );
            word(&mut late, CONTEXT, SKB as u64, 8);
            late[SKB + 40..SKB + 60].copy_from_slice(&cb);
            match mutation {
                0 => word(&mut late, CELL, 6, 8),
                1 => word(&mut late, NET, 8, 8),
                2 => word(&mut late, DEV, 3, 4),
                _ => word(&mut late, CELL + 16, 18, 8),
            }
            fixture.run(&enter, &mut late, false);
            assert_eq!(
                get(&late, CELL + PHASE as usize, 4),
                u64::from(NATIVE_OP_REDIRECT_REQUESTED),
                "entry identity {mutation}"
            );
            assert_eq!(get(&late, CELL + RECEIPT as usize, 4), 0);
        }
    }

    #[test]
    fn captured_restorer_requires_exact_owned_chain() {
        let empty = TcxChain {
            programs: [0; TCX_QUERY_CAPACITY],
            links: [0; TCX_QUERY_CAPACITY],
            count: 0,
            revision: 1,
        };
        let mut chain = empty.clone();
        chain.count = 2;
        chain.programs[..2].copy_from_slice(&[31, 41]);
        chain.links[..2].copy_from_slice(&[51, 0]);
        require_return_chain(&chain, &empty, 41, 31, 51).unwrap();
        for mutation in 0..6 {
            let mut bad = chain.clone();
            match mutation {
                0 => bad.programs.swap(0, 1),
                1 => bad.programs[0] = 32,
                2 => bad.links[0] = 0,
                3 => bad.links[1] = 52,
                4 => bad.count = 3,
                _ => bad.revision = 0,
            }
            assert!(
                require_return_chain(&bad, &empty, 41, 31, 51).is_err(),
                "chain mutation {mutation}"
            );
        }
        assert!(require_return_chain(&chain, &chain, 41, 31, 51).is_err());
    }

    #[test]
    fn captured_entry_target_ceiling_matches_real_emission() {
        let mut fixture = Fixture::new();
        fixture
            .targets
            .resize(MAX_CAPTURED_TARGETS, fixture.targets[0].clone());
        let program = entry(&fixture.config(), &layout()).unwrap();
        assert!(program.len <= STATIC_LIMIT);
        assert!(program.len <= 256 + 8 * MAX_CAPTURED_TARGETS);
        fixture.targets.push(fixture.targets[0].clone());
        assert!(
            matches!(entry(&fixture.config(), &layout()), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn captured_preparation_rejects_unfunded_geometry_before_kernel_admission() {
        for (mtu, targets) in [
            (67, 1),
            (65536, 1),
            (1500, 0),
            (1500, MAX_CAPTURED_TARGETS + 1),
        ] {
            assert_eq!(
                NativeTarget::captured_preparation_bytes(mtu, targets)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
