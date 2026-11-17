use super::{kernel::KernelLayout, receipt::Receipt};
use crate::ebpf::real::{
    btf::Btf,
    process_name::{self, PnameCaptureMode},
    syscall,
};
use anyhow::{Context as _, ensure};
use aya::maps::{Array, MapData};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, Lsm};
use aya::{Ebpf, EbpfLoader};
use honk_ebpf_common::host::*;
use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

pub(super) struct Object {
    pub bpf: Ebpf,
    pub links: Vec<PinnedLink>,
    pub hooks: Vec<(u32, u32)>,
    pub cgroup: File,
    pub pname_mode: PnameCaptureMode,
}

impl Object {
    pub fn active_lsm() -> anyhow::Result<String> {
        let active = std::fs::read_to_string("/sys/kernel/security/lsm")
            .context("Host active LSM list from securityfs")?;
        ensure!(
            active.trim().split(',').any(|name| name == "bpf"),
            "BPF LSM is not active"
        );
        Ok(active)
    }

    pub fn load(
        bytes: &[u8],
        layout: &KernelLayout,
        namespace: u64,
        mark: u32,
    ) -> anyhow::Result<Self> {
        validate_object(bytes)?;
        let mut loader = EbpfLoader::new();
        loader
            .btf(layout.btf())
            .override_global("HOST_SOURCE_NETNS_COOKIE", &namespace, true)
            .override_global("HOST_HAS_BPF_GET_CURRENT_TASK", &1u32, true)
            .override_global("HOST_SOCKET_COOKIE_OFFSET", &layout.socket_cookie, true)
            .override_global("TASK_MM_OFFSET", &layout.task_mm, true)
            .override_global("MM_ARG_START_OFFSET", &layout.mm_arg_start, true)
            .override_global("HOST_CONNECT_LAYOUT", &layout.connect, true)
            .override_global("HOST_BYPASS_MARK", &mark, true);
        let mut bpf = loader.load(bytes)?;
        use aya_obj::generated::bpf_map_type::*;
        for (name, kind, value, count, flags) in [
            (
                "HOST_SOCKETS",
                BPF_MAP_TYPE_ARRAY,
                520,
                8192,
                aya_obj::generated::BPF_F_MMAPABLE,
            ),
            ("HOST_SOCKET_LOCKS", BPF_MAP_TYPE_ARRAY, 8, 8192, 0),
            ("HOST_FACTS", BPF_MAP_TYPE_ARRAY, 136, 262144, 0),
            ("HOST_GATE", BPF_MAP_TYPE_ARRAY, 4, 1, 0),
            ("HOST_SEQUENCE", BPF_MAP_TYPE_ARRAY, 16, 1, 0),
            ("HOST_RETURNS", BPF_MAP_TYPE_HASH, 32, 64, 0),
            ("HOST_IDENTITY_STATS", BPF_MAP_TYPE_PERCPU_ARRAY, 8, 2, 0),
        ] {
            syscall::validate_map_layout(&bpf, name, kind, 4, value, count, flags)?;
        }
        Array::<_, u32>::try_from(bpf.map_mut("HOST_GATE").context("Host gate")?)?.set(0, &0, 0)?;
        Array::<_, HostSequence>::try_from(bpf.map_mut("HOST_SEQUENCE").context("Host sequence")?)?
            .set(0, &HostSequence::new(1), 0)?;
        let pname_mode = if process_name::load_pair(
            &mut bpf,
            "tproxy_wan_cg_sock_create",
            "tproxy_wan_cg_connect4",
        ) {
            PnameCaptureMode::Argv0
        } else {
            PnameCaptureMode::Comm
        };
        let mounts = std::fs::read_to_string("/proc/thread-self/mountinfo")?;
        let mut roots = mounts.lines().filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            if right.split_whitespace().next()? != "cgroup2" {
                return None;
            }
            let fields: Vec<_> = left.split_whitespace().collect();
            (fields.get(3) == Some(&"/"))
                .then(|| fields.get(4).copied())
                .flatten()
        });
        let root = roots
            .next()
            .context("Host requires actual cgroup2 root mount")?;
        ensure!(
            roots.next().is_none() && !root.contains('\\'),
            "ambiguous cgroup2 root mount"
        );
        tracing::debug!(cgroup2_root = %root, "Host opening cgroup2 root");
        let cgroup = File::open(root).with_context(|| format!("Host cgroup2 open: {root}"))?;
        Ok(Self {
            bpf,
            links: Vec::new(),
            hooks: Vec::new(),
            cgroup,
            pname_mode,
        })
    }

    pub fn map(&self, name: &str) -> anyhow::Result<BorrowedFd<'_>> {
        // The Ebpf object owns this descriptor for the returned borrow.
        Ok(unsafe { BorrowedFd::borrow_raw(syscall::map_fd(&self.bpf, name)?) })
    }

    pub fn gate(&mut self, value: u32) -> anyhow::Result<()> {
        let mut gate =
            Array::<_, u32>::try_from(self.bpf.map_mut("HOST_GATE").context("Host gate")?)?;
        gate.set(0, &value, 0)?;
        ensure!(gate.get(&0, 0)? == value, "Host gate readback mismatch");
        Ok(())
    }

    pub fn attach(
        &mut self,
        layout: &KernelLayout,
        pins: &Path,
        receipt: &mut Receipt,
        active_lsm: &str,
    ) -> anyhow::Result<()> {
        let entry = receipt.intent(
            "active_lsm",
            serde_json::json!({"path":"/sys/kernel/security/lsm"}),
        )?;
        receipt.acknowledge(entry, serde_json::json!({"active":active_lsm.trim()}))?;
        tracing::debug!(pins = %pins.display(), "Host attach: pinning maps");
        for (name, map) in self.bpf.maps() {
            if name.starts_with('.') {
                continue;
            }
            let path = pins.join(name);
            tracing::debug!(%name, path = %path.display(), "Host attach: pinning map");
            let entry = receipt.intent("map", serde_json::json!({"name":name,"pin_path":path}))?;
            map.pin(&path)
                .with_context(|| format!("Host map pin {name}: {}", path.display()))?;
            let observed = MapData::from_pin(&path)?.info()?;
            receipt.acknowledge(entry,serde_json::json!({"name":name,"pin_path":path,"id":observed.id(),"key_size":observed.key_size(),"value_size":observed.value_size(),"entries":observed.max_entries()}))?;
        }
        tracing::debug!("Host attach: maps pinned, loading cgroup programs");
        let names = match self.pname_mode {
            PnameCaptureMode::Argv0 => [
                ("tproxy_wan_cg_sock_create", 2u32),
                ("tproxy_wan_cg_connect4", 10),
                ("tproxy_wan_cg_connect6", 11),
                ("tproxy_wan_cg_sendmsg4", 14),
                ("tproxy_wan_cg_sendmsg6", 15),
            ],
            PnameCaptureMode::Comm => [
                ("tproxy_wan_cg_sock_create_comm", 2u32),
                ("tproxy_wan_cg_connect4_comm", 10),
                ("tproxy_wan_cg_connect6_comm", 11),
                ("tproxy_wan_cg_sendmsg4_comm", 14),
                ("tproxy_wan_cg_sendmsg6_comm", 15),
            ],
        };
        for (name, attach_type) in names {
            let path = pins.join(name);
            tracing::debug!(%name, attach_type, path = %path.display(), "Host attach: loading cgroup program");
            let entry = receipt.intent(
                "cgroup_link",
                serde_json::json!({"name":name,"attach_type":attach_type,"pin_path":path}),
            )?;
            let program = self
                .bpf
                .program_mut(name)
                .context("mandatory Host cgroup program missing")?;
            let (link, program_id): (FdLink, u32) = if attach_type == 2 {
                let p: &mut CgroupSock = program.try_into()?;
                tracing::debug!(%name, "Host attach: calling load");
                if p.fd().is_err() {
                    p.load()?;
                }
                let id = p.info()?.id();
                tracing::debug!(%name, %id, "Host attach: calling attach");
                let link = p.attach(&self.cgroup, CgroupAttachMode::Single)?;
                (p.take_link(link)?.try_into()?, id)
            } else {
                let p: &mut CgroupSockAddr = program.try_into()?;
                tracing::debug!(%name, "Host attach: calling load");
                if p.fd().is_err() {
                    p.load()?;
                }
                let id = p.info()?.id();
                tracing::debug!(%name, %id, "Host attach: calling attach");
                let link = p.attach(&self.cgroup, CgroupAttachMode::Single)?;
                (p.take_link(link)?.try_into()?, id)
            };
            let id = link.info()?.id();
            tracing::debug!(%name, link_id = %id, "Host attach: pinning link");
            self.links.push(link.pin(&path)?);
            self.hooks.push((attach_type, program_id));
            receipt.acknowledge(
                entry,
                serde_json::json!({"link_id":id,"program_id":program_id,"pin_path":path}),
            )?;
        }
        tracing::debug!("Host attach: cgroup programs done, loading LSM");
        let path = pins.join("sk_free_security");
        let entry = receipt.intent(
            "lsm_link",
            serde_json::json!({"hook":"sk_free_security","pin_path":path}),
        )?;
        let lsm: &mut Lsm = self
            .bpf
            .program_mut("honk_host_sk_free_security")
            .context("Host LSM missing")?
            .try_into()?;
        tracing::debug!("Host attach: calling lsm.load");
        lsm.load("sk_free_security", layout.btf())?;
        let program_id = lsm.info()?.id();
        tracing::debug!(%program_id, "Host attach: calling lsm.attach");
        let link_id = lsm.attach()?;
        tracing::debug!("Host attach: lsm.take_link");
        let link: FdLink = lsm.take_link(link_id)?.into();
        let id = link.info()?.id();
        tracing::debug!(link_id = %id, path = %path.display(), "Host attach: pinning LSM link");
        self.links.push(link.pin(&path)?);
        receipt.acknowledge(
            entry,
            serde_json::json!({"link_id":id,"program_id":program_id,"pin_path":path}),
        )?;
        tracing::debug!("Host attach: LSM done, entering identity_canary");
        self.identity_canary(receipt)
    }

    fn identity_canary(&self, receipt: &mut Receipt) -> anyhow::Result<()> {
        tracing::debug!("Host identity_canary: start");
        let intent =
            receipt.intent("identity_canary", serde_json::json!({"map":"HOST_SOCKETS"}))?;
        tracing::debug!("Host identity_canary: creating socket");
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        let mut cookie = 0u64;
        let mut len = 8u32;
        ensure!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    57,
                    (&mut cookie as *mut u64).cast(),
                    &mut len,
                )
            } == 0,
            "Host canary SO_COOKIE: {}",
            std::io::Error::last_os_error()
        );
        ensure!(len == 8 && cookie != 0, "Host canary cookie invalid");
        tracing::debug!(%cookie, "Host identity_canary: got cookie, checking bank");
        let key = (cookie & (HOST_SOCKET_BUCKETS as u64 - 1)) as u32;
        let bank = crate::ebpf::host_bank::HostSocketBank::map(self.map("HOST_SOCKETS")?)?;
        tracing::debug!(%key, "Host identity_canary: mapped snapshot before");
        let before = bank.read(key)?;
        let slot = before
            .value
            .iter()
            .find(|entry| entry.cookie == cookie)
            .context("Host create canary missing actual slot")?;
        ensure!(
            slot.pid == std::process::id() && slot.flags & HOST_SOCKET_PROCESS_PRESENT != 0,
            "Host create canary identity mismatch"
        );
        tracing::debug!("Host identity_canary: drop socket");
        drop(socket);
        tracing::debug!("Host identity_canary: mapped snapshot after");
        let after = bank.read(key)?;
        ensure!(
            after.version > before.version
                && !after.value.iter().any(|entry| entry.cookie == cookie),
            "Host final-retirement canary did not clear actual slot"
        );
        tracing::debug!("Host identity_canary: acknowledge receipt");
        receipt.acknowledge(intent,serde_json::json!({"socket_cookie":cookie,"bucket":key,"pid":slot.pid,"captured":true,"retired":true}))
    }
}

fn validate_object(bytes: &[u8]) -> anyhow::Result<()> {
    let object = aya_obj::Object::parse(bytes)?;
    let data = object
        .btf
        .as_ref()
        .context("Host object BTF missing")?
        .to_bytes();
    let btf = Btf::parse(&data).context("invalid Host object BTF")?;
    for (name, map) in &object.maps {
        ensure!(
            map.pinning() == aya_obj::maps::PinningType::None,
            "Host object requests implicit map pinning"
        );
        ensure!(
            name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "HOST_SOCKETS"
                        | "HOST_SOCKET_LOCKS"
                        | "HOST_FACTS"
                        | "HOST_GATE"
                        | "HOST_SEQUENCE"
                        | "HOST_RETURNS"
                        | "HOST_IDENTITY_STATS"
                ),
            "foreign map in narrow Host object: {name}"
        );
    }
    let bank_type = |name: &str| -> anyhow::Result<u32> {
        let Some(aya_obj::maps::Map::Btf(map)) = object.maps.get(name) else {
            anyhow::bail!("missing typed Host map {name}");
        };
        Ok(map.def.btf_value_type_id)
    };
    crate::ebpf::host_bank::validate_btf(
        &btf,
        bank_type("HOST_SOCKETS")?,
        bank_type("HOST_SOCKET_LOCKS")?,
    )?;
    for (name, size) in [("HOST_FACTS", 136), ("HOST_SEQUENCE", 16)] {
        let Some(aya_obj::maps::Map::Btf(map)) = object.maps.get(name) else {
            anyhow::bail!("missing typed Host map {name}")
        };
        let owner = btf
            .resolve_composite(map.def.btf_value_type_id)
            .context("Host map wrapper type")?;
        let (lock, offset) = btf
            .direct_member(owner, "lock")
            .context("Host native lock")?;
        let lock = btf.resolve_modifiers(lock).context("Host lock type")?;
        let (padding, pad_offset) = btf
            .direct_member(owner, "padding")
            .context("Host lock padding")?;
        let (value, value_offset) = btf
            .direct_member(owner, "value")
            .context("Host locked value")?;
        ensure!(
            btf.u32_at(owner + 8) == Some(size)
                && offset == 0
                && btf.kind(lock) == Some(4)
                && btf.string(btf.u32_at(lock).context("Host lock name")?) == Some("bpf_spin_lock")
                && btf.u32_at(lock + 8) == Some(4)
                && btf.sized_member_offset("bpf_spin_lock", "val", 4) == Some(0)
                && pad_offset == 4
                && btf.type_size(padding) == Some(4)
                && value_offset == 8
                && btf.type_size(value) == Some(size - 8),
            "Host native locked map BTF mismatch: {name}"
        );
    }
    for (name, size, fields) in [
        (
            "HostSourceFacts",
            80,
            &[
                ("netns_cookie", 0, 8),
                ("attachment", 8, 8),
                ("socket_cookie", 16, 8),
                ("return_generation", 24, 8),
                ("output_ifindex", 32, 4),
                ("skb_mark", 36, 4),
                ("socket_mark", 40, 4),
                ("pid", 44, 4),
                ("pname", 48, 16),
                ("flags", 64, 4),
                ("stage", 68, 2),
                ("family", 70, 2),
                ("operation_incarnation", 72, 8),
            ][..],
        ),
        (
            "HostReceipt",
            24,
            &[("id", 0, 8), ("captured_ns", 8, 8), ("expires_ns", 16, 8)][..],
        ),
        (
            "HostPacketMetadata",
            128,
            &[
                ("magic", 0, 4),
                ("version", 4, 2),
                ("length", 6, 2),
                ("receipt", 8, 24),
                ("facts", 32, 80),
                ("original_l3_len", 112, 4),
                ("gso_size", 116, 4),
                ("gso_segs", 120, 4),
                ("representation", 124, 4),
            ][..],
        ),
        (
            "HostSocketEntry",
            64,
            &[
                ("cookie", 0, 8),
                ("socket_address", 8, 8),
                ("pid", 16, 4),
                ("pname", 20, 16),
                ("flags", 36, 4),
                ("operation_incarnation", 40, 8),
                ("disconnect_generation", 48, 4),
                ("selection", 52, 4),
                ("output_ifindex", 56, 4),
                ("reserved", 60, 4),
            ][..],
        ),
        (
            "HostReturnDevice",
            32,
            &[
                ("generation", 0, 8),
                ("ifindex", 8, 4),
                ("flags", 12, 4),
                ("mac", 16, 6),
                ("peer_mac", 22, 6),
                ("reserved", 28, 4),
            ][..],
        ),
    ] {
        let ty = btf
            .find_type(4, name)
            .with_context(|| format!("missing Host BTF payload {name}"))?;
        ensure!(btf.u32_at(ty + 8) == Some(size), "Host payload size {name}");
        for &(member, offset, width) in fields {
            ensure!(
                btf.sized_member_offset(name, member, width) == Some(offset),
                "Host payload field {name}.{member}"
            );
        }
    }
    Ok(())
}
