//! Concrete Host capture custody; source admission is one-shot and fail-closed.
pub(crate) mod custody;
mod features;
pub(crate) mod kernel;
mod namespace;
pub(crate) mod native;
mod object;
pub(crate) mod receipt;
pub(crate) mod sys;

use anyhow::{Context as _, ensure};
use custody::CustodySnapshot;
use honk_ebpf_common::{host::*, xdp::CaptureAuthority};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_xsk::device::DeviceInfo;
use honk_xsk::{
    BindMode, DecodeError, HostPrograms, HostSourceConfig, HostSourcePrograms, HostTcxAttachment,
    PersistentAttachment, Port, PortConfig,
};
use namespace::{PrivatePair, in_namespace};
use std::cell::RefCell;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) struct HostPrepare<'a> {
    pub source_interfaces: &'a [String],
    pub source_xdp: &'a [(u32, u32)],
    pub object: &'a [u8],
    pub authority: CaptureAuthority,
    pub bypass_mark: u32,
    pub pin_root: &'a Path,
    pub data_dir: &'a Path,
    pub budget: Arc<MemoryBudget>,
    pub native: Option<Arc<crate::ebpf::native::NativePublication>>,
}

pub(super) struct HostPacket {
    pub facts: HostSourceFacts,
    pub receipt: HostReceipt,
    pub l3_offset: usize,
    pub l3_len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Prepared,
    Admitted,
    Closed,
    Retained,
    Finished,
}

pub(super) struct HostCapture {
    authority: CaptureAuthority,
    state: State,
    source_namespace: File,
    pair: PrivatePair,
    object: object::Object,
    programs: HostPrograms,
    source: HostSourcePrograms,
    source_links: Vec<HostTcxAttachment>,
    return_link: HostTcxAttachment,
    selector: OwnedFd,
    xdp: PersistentAttachment,
    custody: [Arc<CustodySnapshot>; 2],
    cgroups: sys::Cgroups,
    features: [features::Features; 2],
    returns: Vec<HostReturnDevice>,
    mtu: u32,
    xsk: RefCell<Option<OwnedFd>>,
    grace: sys::Grace,
    receipt: Arc<parking_lot::Mutex<receipt::Receipt>>,
    native: Option<(
        Arc<crate::ebpf::native::NativePublication>,
        Arc<native::HostNativeTarget>,
    )>,
    pins: PathBuf,
    budget: Arc<MemoryBudget>,
    memory: Option<MemoryReservation>,
    checked: Option<std::time::Instant>,
}

impl HostCapture {
    pub(super) fn prepare_closed(spec: HostPrepare<'_>) -> anyhow::Result<Self> {
        ensure!(
            !spec.source_interfaces.is_empty() && spec.source_interfaces.len() <= 64,
            "Host requires 1..64 explicit source interfaces"
        );
        ensure!(
            spec.source_xdp.len() <= 256,
            "Host Transit attachment inventory exceeds bound"
        );
        ensure!(
            spec.bypass_mark != 0 && spec.bypass_mark & honk_ebpf_common::CLASSIFIED_MARK == 0,
            "invalid Host bypass mark"
        );
        ensure!(
            spec.authority.namespace_cookie != 0
                && spec.authority.attachment_generation != 0
                && spec.authority.scope != 0
                && spec.authority.reserved == 0,
            "invalid Host authority"
        );
        kernel::zero_monotonic_namespace()?;
        tracing::debug!("Host opening source netns");
        let source_namespace = File::open("/proc/thread-self/ns/net")?;
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        ensure!(
            crate::netlink::fib::namespace_cookie(socket.as_raw_fd())?
                == spec.authority.namespace_cookie,
            "Host source namespace mismatch"
        );
        let memory = spec
            .budget
            .reserve(96 * 1024 * 1024)
            .context("Host fixed maps, loader and custody memory capacity")?;
        let layout = kernel::KernelLayout::load(&spec.budget)?;
        let active_lsm = object::Object::active_lsm()?;
        let pins = spec
            .pin_root
            .join(format!("host-{}", spec.authority.namespace_cookie));
        let mut receipt = receipt::Receipt::create(
            spec.data_dir,
            spec.authority.namespace_cookie,
            spec.authority.attachment_generation,
            &pins,
        )?;
        let pin_intent = receipt.intent("pin_directory", serde_json::json!({"path":pins}))?;
        std::fs::DirBuilder::new().mode(0o700).create(&pins)?;
        let meta = std::fs::metadata(&pins)?;
        receipt.acknowledge(
            pin_intent,
            serde_json::json!({"dev":meta.dev(),"inode":meta.ino()}),
        )?;
        // Any failure beyond this point may leave pinned kernel allocations.
        let mut retained_memory = std::mem::ManuallyDrop::new(memory);
        let mut nl = crate::netlink::NlSock::new()?;
        let all = nl.dump_links()?;
        let mut returns = Vec::with_capacity(spec.source_interfaces.len());
        let mut mtu = 65535 - HOST_RETURN_LEN as u32;
        for name in spec.source_interfaces {
            ensure!(
                !returns.iter().any(|r: &HostReturnDevice| all
                    .iter()
                    .any(|link| link.name == *name && link.ifindex.get() == r.ifindex)),
                "duplicate Host source"
            );
            let link = all
                .iter()
                .find(|link| link.name == *name)
                .context("Host source interface absent")?;
            ensure!(
                link.arphrd == 1
                    && link.master.is_none()
                    && link.kind.as_deref().is_none_or(|kind| kind == "veth"),
                "Host source is not plain Ethernet"
            );
            let mac = link.mac.context("Host source Ethernet address absent")?;
            ensure!(
                name.len() < libc::IFNAMSIZ,
                "Host source name exceeds kernel extent"
            );
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            for (out, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
                *out = byte as libc::c_char;
            }
            ensure!(
                unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &mut request) } == 0,
                "Host source MTU readback: {}",
                std::io::Error::last_os_error()
            );
            let source_mtu = u32::try_from(unsafe { request.ifr_ifru.ifru_mtu })?;
            mtu = mtu.min(source_mtu);
            returns.push(HostReturnDevice {
                generation: honk_datapath::ScopeId::allocate()
                    .context("Host return incarnation exhausted")?
                    .as_u64(),
                ifindex: link.ifindex.get(),
                flags: 0,
                mac,
                peer_mac: mac,
                reserved: 0,
            });
        }
        ensure!(mtu >= 1280, "Host return output MTU below 1280");
        let pair = PrivatePair::create(spec.authority.attachment_generation, &mut receipt)?;
        let mut object = object::Object::load(
            spec.object,
            &layout,
            spec.authority.namespace_cookie,
            spec.bypass_mark,
        )?;
        {
            let mut map = aya::maps::HashMap::<_, u32, HostReturnDevice>::try_from(
                object
                    .bpf
                    .map_mut("HOST_RETURNS")
                    .context("Host return map")?,
            )?;
            for value in &returns {
                ensure!(
                    value.ifindex != pair.tx,
                    "private device cannot be return target"
                );
                map.insert(&value.ifindex, value, 1)?;
            }
        }
        tracing::debug!("Host prepare_closed: attach() done, loading HostSourcePrograms");
        object.attach(&layout, &pins, &mut receipt, &active_lsm)?;
        let source_config = HostSourceConfig {
            source_netns: spec.authority.namespace_cookie,
            attachment: spec.authority.attachment_generation,
            private_tx: pair.tx,
            bypass_mark: spec.bypass_mark,
            tx_mac: pair.tx_mac,
            rx_mac: pair.device.mac,
            skb_sk_offset: layout.skb_sk,
            sock_net_pointer_offset: layout.sock_net,
            net_cookie_offset: layout.net_cookie,
            skb_destructor_offset: layout.skb_destructor,
            skb_truesize_offset: layout.skb_truesize,
            sock_wmem_offset: layout.connect.wmem_alloc,
            sock_refcnt_offset: layout.connect.refcnt,
            sock_write_queue_len_offset: layout.connect.write_queue_len,
            sock_wfree: layout.sock_wfree,
        };
        let source = HostSourcePrograms::load(
            &source_config,
            layout.btf(),
            object.map("HOST_FACTS")?,
            object.map("HOST_GATE")?,
            object.map("HOST_SEQUENCE")?,
            (
                object.map("HOST_SOCKETS")?,
                object.map("HOST_SOCKET_LOCKS")?,
            ),
            object.map("HOST_RETURNS")?,
        )?;
        tracing::debug!(
            "Host prepare_closed: HostSourcePrograms loaded, calling in_namespace for HostPrograms"
        );
        let programs = in_namespace(&pair.namespace, || {
            Ok(HostPrograms::load(
                layout.btf(),
                pair.device.ifindex,
                pair.tx,
                spec.authority.attachment_generation,
                spec.authority.namespace_cookie,
                pair.tx_mac,
                pair.device.mac,
                object.map("HOST_FACTS")?,
                object.map("HOST_GATE")?,
                object.map("HOST_RETURNS")?,
            )?)
        })?;
        tracing::debug!("Host prepare_closed: HostPrograms loaded, creating source_links");
        let mut source_links = Vec::with_capacity(returns.len());
        let mut expected_tcx = Vec::with_capacity(returns.len() + 1);
        for value in &returns {
            let root = pins.join(format!("source-{}", value.ifindex));
            std::fs::DirBuilder::new().mode(0o700).create(&root)?;
            let intent = receipt.intent(
                "source_tcx",
                serde_json::json!({"ifindex":value.ifindex,"attach_type":47,"pin_path":root}),
            )?;
            let (program, id) = source.source();
            let (guard, guard_id) = source.guard();
            let link =
                HostTcxAttachment::create(value.ifindex, 47, program, id, guard, guard_id, &root)?;
            expected_tcx.push((value.ifindex, 47, id, link.id()));
            receipt.acknowledge(
                intent,
                serde_json::json!({"program_id":id,"link_id":link.id(),"guard_id":guard_id}),
            )?;
            source_links.push(link);
        }
        tracing::debug!("Host prepare_closed: source_links done, attaching return");
        let return_root = pins.join("return");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&return_root)?;
        let intent = receipt.intent(
            "return_tcx",
            serde_json::json!({"ifindex":pair.tx,"attach_type":46,"pin_path":return_root}),
        )?;
        let return_link = programs.attach_return(&return_root)?;
        let return_program = sys::link_program(return_link.as_fd())?;
        expected_tcx.push((pair.tx, 46, return_program, return_link.id()));
        receipt.acknowledge(intent,serde_json::json!({"link_id":return_link.id(),"program_id":return_program,"guard_id":sys::newly_pinned_id(&return_root.join("guard"))?}))?;
        tracing::debug!("Host prepare_closed: return done, creating private_xdp");
        let xdp_root = pins.join("private_xdp");
        std::fs::DirBuilder::new().mode(0o700).create(&xdp_root)?;
        let intent=receipt.intent("private_xdp",serde_json::json!({"ifindex":pair.device.ifindex,"child_cookie":pair.cookie,"pin_path":xdp_root}))?;
        let xdp = in_namespace(&pair.namespace, || {
            Ok(PersistentAttachment::create(
                pair.device.ifindex,
                programs.programs(),
                &xdp_root,
            )?)
        })?;
        tracing::debug!("Host prepare_closed: private_xdp done, attaching selector");
        receipt.acknowledge(intent,serde_json::json!({"guard_id":programs.programs().discover_prog_id(),"data_id":programs.programs().data_prog_id()}))?;
        let tx_features = features::Features::configure(&pair.tx_name)?;
        let rx_features = in_namespace(&pair.namespace, || {
            features::Features::configure(&pair.device.name)
        })?;
        let intent = receipt.intent(
            "selector",
            serde_json::json!({"attach_type":1,"pin_path":pins.join("selector")}),
        )?;
        let selector =
            sys::attach_selector(source.selector().0, &object.cgroup, &pins.join("selector"))?;
        object.hooks.push((1, source.selector().1));
        receipt.acknowledge(intent,serde_json::json!({"program_id":source.selector().1,"link_id":sys::identity(selector.as_fd())?.1}))?;
        tracing::debug!("Host prepare_closed: selector done, capturing cgroups");
        let cgroups = sys::Cgroups::capture(&object.cgroup, &object.hooks, &mut receipt)?;
        let selected: Vec<_> = returns.iter().map(|r| r.ifindex).collect();
        let mut owned = Vec::with_capacity(4 + spec.source_xdp.len());
        owned.extend([
            source.source().1,
            source.guard().1,
            source.selector().1,
            return_program,
        ]);
        owned.extend(spec.source_xdp.iter().map(|&(_, id)| id));
        tracing::debug!("Host prepare_closed: cgroups done, source_custody");
        let source_custody = Arc::new(CustodySnapshot::capture(
            source_namespace.as_fd(),
            &owned,
            [pair.tx, 0],
            &selected,
            &expected_tcx,
            spec.source_xdp,
            None,
            &spec.budget,
        )?);
        let receipt = Arc::new(parking_lot::Mutex::new(receipt));
        let native_write = spec
            .native
            .as_ref()
            .map(|p| p.write(crate::ebpf::native::NativeReason::Startup))
            .transpose()?;
        let native_target = if let Some(publication) = &spec.native {
            let [root, claims, scratch] = publication.host_map_fds();
            let target = native::HostNativeTarget::load(
                source_config,
                spec.authority.scope,
                &layout,
                honk_xsk::HostNativeMaps {
                    root,
                    claims,
                    scratch,
                    gate: object.map("HOST_GATE")?,
                    sequence: object.map("HOST_SEQUENCE")?,
                    sockets: object.map("HOST_SOCKETS")?,
                    socket_locks: object.map("HOST_SOCKET_LOCKS")?,
                    returns: object.map("HOST_RETURNS")?,
                },
                receipt.clone(),
                &spec.budget,
                &pins,
            )?;
            publication.register_host(
                target.clone(),
                native_write
                    .as_ref()
                    .context("Host Native writer missing")?,
            )?;
            Some(target)
        } else {
            None
        };
        if let Some(target) = &native_target {
            source_custody.register_native(target)?;
            target.set_custody(source_custody.clone())?;
            source_custody.revalidate()?;
        }
        tracing::debug!("Host prepare_closed: source_custody done, child_custody via in_namespace");
        let child_custody = in_namespace(&pair.namespace, || {
            Ok(Arc::new(CustodySnapshot::capture(
                pair.namespace.as_fd(),
                &[
                    programs.programs().discover_prog_id(),
                    programs.programs().data_prog_id(),
                ],
                [0, pair.device.ifindex],
                &[],
                &[],
                &[(pair.device.ifindex, programs.programs().discover_prog_id())],
                None,
                &spec.budget,
            )?))
        })?;
        let intent = receipt.lock().intent(
            "namespace_custody",
            serde_json::json!({"hostile_privileged_mutation_excluded":true}),
        )?;
        receipt.lock().acknowledge(intent,serde_json::json!({"source":source_custody.evidence(),"child":child_custody.evidence()}))?;
        tracing::debug!("Host prepare_closed: custody done, Grace::new");
        let grace = sys::Grace::new()?;
        let mut kernel_bytes = programs
            .memory_bytes()?
            .checked_add(grace.memory_bytes()?)
            .context("Host kernel memory overflow")?;
        for (_, program) in object.bpf.programs() {
            if let Ok(fd) = program.fd() {
                kernel_bytes = kernel_bytes
                    .checked_add(sys::memory_bytes(fd.as_fd())?)
                    .context("Host program memory overflow")?;
            }
        }
        for (name, _) in object.bpf.maps() {
            kernel_bytes = kernel_bytes
                .checked_add(sys::memory_bytes(object.map(name)?)?)
                .context("Host map memory overflow")?;
        }
        for fd in [source.source().0, source.guard().0, source.selector().0] {
            kernel_bytes = kernel_bytes
                .checked_add(sys::memory_bytes(fd)?)
                .context("Host raw program memory overflow")?;
        }
        ensure!(
            kernel_bytes <= 64 * 1024 * 1024,
            "Host kernel allocations exceed reserved fixed-map allowance"
        );
        let memory_intent = receipt.lock().intent(
            "kernel_memory",
            serde_json::json!({"reserved_bytes":retained_memory.bytes(),"reservation_scope":"fixed maps and loader; excludes separately charged kernel BTF and custody snapshots","kernel_limit_bytes":64*1024*1024}),
        )?;
        receipt.lock().acknowledge(memory_intent,serde_json::json!({"kernel_bytes":kernel_bytes,"retained_fixed_reservation_bytes":retained_memory.bytes(),"userspace_allowance_bytes":32*1024*1024,"userspace_allowance_includes_kernel_btf":false,"cold_kernel_btf_peak_reserved_bytes":layout.memory_bytes(),"cold_kernel_btf_retained_after_prepare":false}))?;
        tracing::debug!("Host prepare_closed: kernel_bytes done, receipt.phase closed");
        receipt.lock().phase("closed")?;
        if let Some(writer) = native_write {
            writer.commit();
        }
        Ok(Self {
            authority: spec.authority,
            state: State::Prepared,
            source_namespace,
            pair,
            object,
            programs,
            source,
            source_links,
            return_link,
            selector,
            xdp,
            custody: [source_custody, child_custody],
            cgroups,
            features: [tx_features, rx_features],
            returns,
            mtu,
            xsk: RefCell::new(None),
            grace,
            receipt,
            native: spec.native.zip(native_target),
            pins,
            budget: spec.budget,
            memory: Some(unsafe { std::mem::ManuallyDrop::take(&mut retained_memory) }),
            checked: None,
        })
    }

    pub(super) fn metadata_failures(&self) -> std::io::Result<u64> {
        self.programs.programs().metadata_failures()
    }

    pub(super) fn private_device(&self) -> &DeviceInfo {
        &self.pair.device
    }
    pub(super) fn output_mtu(&self) -> u32 {
        self.mtu
    }
    pub(super) fn pname_support(&self) -> crate::ebpf::PnameSupport {
        use crate::ebpf::{PnameSupport, real::process_name::PnameCaptureMode};
        if self.state != State::Admitted {
            return PnameSupport::Unavailable;
        }
        match self.object.pname_mode {
            PnameCaptureMode::Argv0 => PnameSupport::HostFull,
            PnameCaptureMode::Comm => PnameSupport::HostThreadName,
        }
    }
    pub(super) fn watch_fds(&self) -> [BorrowedFd<'_>; 2] {
        [self.custody[0].as_fd(), self.custody[1].as_fd()]
    }

    pub(super) fn open_port<L>(&self, config: PortConfig) -> anyhow::Result<Port<L>> {
        ensure!(
            self.state == State::Prepared && self.xsk.borrow().is_none(),
            "Host private Port already opened or owner closed"
        );
        let required =
            self.pair
                .device
                .validate_port_config(BindMode::Copy, config, HOST_METADATA_LEN)?;
        let port = in_namespace(&self.pair.namespace, || {
            self.pair.device.validate_current()?;
            Ok(Port::open_device(
                self.pair.device.ifindex,
                0,
                BindMode::Copy,
                config,
                self.pair.device.mtu,
                required > 1,
                HOST_METADATA_LEN,
                &self.budget,
            )?)
        })?;
        ensure!(
            !port.zerocopy()
                && crate::netlink::fib::namespace_cookie(port.as_raw_fd())? == self.pair.cookie,
            "Host private Copy namespace mismatch"
        );
        *self.xsk.borrow_mut() = Some(port.as_fd().try_clone_to_owned()?);
        Ok(port)
    }

    pub(super) fn decode(
        &self,
        segments: &[&[u8]],
        metadata: &[u8],
        queue: u32,
        now: u64,
    ) -> Result<HostPacket, DecodeError> {
        if self.state != State::Admitted || queue != 0 {
            return Err(DecodeError::Authority);
        }
        let envelope = HostPacketMetadata::decode(metadata).ok_or(DecodeError::Metadata)?;
        if !envelope.receipt.admits(now) || !self.owns(&envelope.facts) {
            return Err(DecodeError::Authority);
        }
        let total = segments
            .iter()
            .try_fold(0usize, |len, segment| len.checked_add(segment.len()))
            .ok_or(DecodeError::Truncated)?;
        let mut header = [0u8; 54];
        let mut copied = 0;
        for segment in segments {
            let count = segment.len().min(header.len() - copied);
            header[copied..copied + count].copy_from_slice(&segment[..count]);
            copied += count;
            if copied == header.len() {
                break;
            }
        }
        if copied < 34 || header[..6] != self.pair.device.mac || header[6..12] != self.pair.tx_mac {
            return Err(DecodeError::Ethernet);
        }
        let ipv6 = header[12..14] == [0x86, 0xdd];
        if ipv6 && envelope.facts.family != 10 {
            return Err(DecodeError::Ip);
        }
        let length = if ipv6 {
            if copied < 54 || header[12..14] != [0x86, 0xdd] || header[14] >> 4 != 6 {
                return Err(DecodeError::Ip);
            }
            40 + usize::from(u16::from_be_bytes([header[18], header[19]]))
        } else {
            if header[12..14] != [8, 0] || header[14] >> 4 != 4 || header[14] & 15 < 5 {
                return Err(DecodeError::Ip);
            }
            let length = usize::from(u16::from_be_bytes([header[16], header[17]]));
            if length < usize::from(header[14] & 15) * 4 {
                return Err(DecodeError::Ip);
            }
            length
        };
        if length + 14 != total || length > 65535 {
            return Err(DecodeError::Ip);
        }
        Ok(HostPacket {
            facts: envelope.facts,
            receipt: envelope.receipt,
            l3_offset: 14,
            l3_len: length,
        })
    }

    fn owns(&self, facts: &HostSourceFacts) -> bool {
        facts.is_valid()
            && facts.stage == HOST_STAGE_TCX_EGRESS
            && facts.netns_cookie == self.authority.namespace_cookie
            && facts.attachment == self.authority.attachment_generation
            && self.returns.iter().any(|r| {
                r.ifindex == facts.output_ifindex && r.generation == facts.return_generation
            })
    }

    pub(super) fn encode_return(
        &self,
        facts: &HostSourceFacts,
        l3_len: usize,
        ipv6: bool,
        header: &mut [u8],
    ) -> anyhow::Result<usize> {
        ensure!(
            matches!(self.state, State::Admitted | State::Closed) && self.owns(facts),
            "Host return authority retired or mismatched"
        );
        ensure!(!ipv6 || facts.family == 10, "Host return family mismatch");
        ensure!(
            l3_len >= if ipv6 { 40 } else { 20 }
                && l3_len <= self.mtu as usize
                && header.len() >= 54,
            "Host return extent exceeds admitted output MTU"
        );
        header[..6].copy_from_slice(&self.pair.tx_mac);
        header[6..12].copy_from_slice(&self.pair.device.mac);
        header[12..14].copy_from_slice(&if ipv6 { 0x86ddu16 } else { 0x0800u16 }.to_be_bytes());
        HostReturnContext {
            magic: *b"HRV1",
            version: 1,
            length: 40,
            direction: 1,
            family: if ipv6 { 6 } else { 4 },
            attachment: facts.attachment,
            generation: facts.return_generation,
            target: facts.output_ifindex,
            l3_len: l3_len as u32,
        }
        .encode(&mut header[14..54])
        .context("Host return header extent")?;
        Ok(54)
    }

    pub(super) fn validate_current(&mut self) -> anyhow::Result<()> {
        ensure!(
            matches!(self.state, State::Prepared | State::Admitted),
            "Host capture is terminal"
        );
        let checked: anyhow::Result<()> = (|| {
            for snapshot in &self.custody {
                snapshot.revalidate()?;
            }
            let now = std::time::Instant::now();
            if self.state == State::Admitted
                && self.checked.is_some_and(|checked| {
                    now.duration_since(checked) < std::time::Duration::from_secs(1)
                })
            {
                return Ok(());
            }
            let current = File::open("/proc/thread-self/ns/net")?.metadata()?;
            let held = self.source_namespace.metadata()?;
            ensure!(
                current.dev() == held.dev() && current.ino() == held.ino(),
                "Host execution namespace changed"
            );
            self.cgroups.check()?;
            for feature in &mut self.features {
                feature.check()?;
            }
            for link in &self.source_links {
                link.check()?;
            }
            self.return_link.check()?;
            ensure!(
                sys::link_program(self.selector.as_fd())? == self.source.selector().1,
                "Host selector link changed"
            );
            self.checked = Some(now);
            Ok(())
        })();
        if let Err(error) = checked {
            let close = self.close_capture();
            return Err(error).context(format!("Host custody invalidated; close={close:?}"));
        }
        Ok(())
    }

    pub(super) fn admit(
        &mut self,
        xsk: BorrowedFd<'_>,
        consumers_ready: bool,
    ) -> anyhow::Result<()> {
        ensure!(
            self.state == State::Prepared && consumers_ready,
            "Host consumers not ready or capture already used"
        );
        self.validate_current()?;
        let retained = self.xsk.borrow();
        let owned = retained.as_ref().context("Host Port not opened")?;
        let cookie = |fd: BorrowedFd<'_>| -> anyhow::Result<u64> {
            let mut cookie = 0u64;
            let mut len = 8;
            ensure!(
                unsafe {
                    libc::getsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        57,
                        (&mut cookie as *mut u64).cast(),
                        &mut len,
                    )
                } == 0,
                "Host XSK cookie readback"
            );
            ensure!(len == 8 && cookie != 0, "Host XSK cookie invalid");
            Ok(cookie)
        };
        ensure!(
            cookie(owned.as_fd())? == cookie(xsk)?
                && crate::netlink::fib::namespace_cookie(xsk.as_raw_fd())? == self.pair.cookie,
            "Host admit received foreign XSK"
        );
        let mut options = 0u32;
        let mut options_len = 4u32;
        ensure!(
            unsafe {
                libc::getsockopt(
                    xsk.as_raw_fd(),
                    283,
                    8,
                    (&mut options as *mut u32).cast(),
                    &mut options_len,
                )
            } == 0
                && options_len == 4
                && options & 1 == 0,
            "Host XSK actual Copy mode unavailable"
        );
        let port_intent=self.receipt.lock().intent("private_port",serde_json::json!({"metadata_headroom":HOST_METADATA_LEN,"queue":0,"ifindex":self.pair.device.ifindex}))?;
        self.receipt.lock().acknowledge(port_intent,serde_json::json!({"socket_cookie":cookie(xsk)?,"namespace_cookie":self.pair.cookie,"ifindex":self.pair.device.ifindex,"queue":0,"options":options,"zero_copy":false,"mtu":self.pair.device.mtu}))?;
        self.programs.programs().insert_xsk(0, xsk)?;
        drop(retained);
        let opened: anyhow::Result<()> = (|| {
            in_namespace(&self.pair.namespace, || {
                Ok(self.xdp.replace(self.programs.programs())?)
            })?;
            in_namespace(&self.pair.namespace, || {
                Arc::get_mut(&mut self.custody[1])
                    .context("Host child custody unexpectedly shared")?
                    .acknowledge_xdp(
                        self.pair.device.ifindex,
                        self.programs.programs().discover_prog_id(),
                        self.programs.programs().data_prog_id(),
                    )
            })?;
            self.grace.barrier()?;
            self.object.gate(1)?;
            self.receipt.lock().phase("open")?;
            Ok(())
        })();
        self.state = State::Admitted;
        if let Err(error) = opened {
            let close = self.close_capture();
            return Err(error).context(format!("Host admission failed; close={close:?}"));
        }
        Ok(())
    }

    pub(super) fn close_capture(&mut self) -> anyhow::Result<()> {
        if matches!(self.state, State::Closed | State::Finished) {
            return Ok(());
        }
        ensure!(
            self.state != State::Retained,
            "Host custody unresolved; receipt retained"
        );
        self.state = State::Retained;
        if let Some((publication, _)) = &self.native {
            publication.quiesce(crate::ebpf::native::NativeReason::Shutdown)?;
            publication.close_host_admission()?;
        }
        self.object.gate(0)?;
        self.receipt.lock().phase("closing")?;
        for link in &mut self.source_links {
            link.guard(self.source.source().0, self.source.guard().0)?;
        }
        in_namespace(&self.pair.namespace, || {
            Ok(self.xdp.guard(self.programs.programs())?)
        })?;
        self.grace.barrier()?;
        self.programs.programs().delete_xsk(0)?;
        self.xsk.borrow_mut().take();
        self.receipt.lock().phase("closed")?;
        self.state = State::Closed;
        Ok(())
    }

    pub(super) fn finish_close(&mut self) -> anyhow::Result<()> {
        if self.state == State::Finished {
            return Ok(());
        }
        self.close_capture()?;
        self.programs.guard_return(&mut self.return_link)?;
        self.grace.barrier()?;
        let bank = crate::ebpf::host_bank::HostSocketBank::map(self.object.map("HOST_SOCKETS")?)?;
        let mut selected = 0usize;
        for index in 0..HOST_SOCKET_BUCKETS as u32 {
            selected += bank
                .read(index)?
                .value
                .iter()
                .filter(|entry| {
                    entry.cookie != 0
                        && !matches!(
                            entry.selection,
                            HOST_SOCKET_UNSELECTED | HOST_SOCKET_KERNEL | HOST_SOCKET_BORN_NEW
                        )
                })
                .count();
        }
        let native_source_owners = match &self.native {
            Some((_, target)) => target
                .retained_sources()
                .context("Host Native source retirement was not observed")?,
            None => 0,
        };
        if selected != 0 || native_source_owners != 0 {
            let intent = self.receipt.lock().intent(
                "guarded_stop",
                serde_json::json!({"external_socket_owners":selected,"native_source_owners":native_source_owners}),
            )?;
            self.receipt.lock().acknowledge(intent,serde_json::json!({"gate":0,"source_guards":true,"return_guard":true,"reader_grace":true,"external_socket_owners":selected,"native_source_owners":native_source_owners}))?;
            self.receipt.lock().phase("guarded-retained")?;
            self.state = State::Retained;
            return Ok(());
        }
        if let Some((_, target)) = &self.native {
            target.finish_close()?;
        }
        self.pair.remove(&mut self.receipt.lock())?;
        self.receipt.lock().retire_pins(&self.pins)?;
        self.object.links.clear();
        self.receipt.lock().finish()?;
        self.state = State::Finished;
        // FD closure does not acknowledge deferred kernel allocation release.
        if let Some(memory) = self.memory.take() {
            std::mem::forget(memory);
        }
        Ok(())
    }
}

impl Drop for HostCapture {
    fn drop(&mut self) {
        if self.state != State::Finished {
            let _ = self.close_capture();
            if let Some(memory) = self.memory.take() {
                std::mem::forget(memory);
            }
        }
    }
}
