use super::*;

pub(crate) fn validate_config(config: &Config) -> anyhow::Result<()> {
    let Some(datapath) = config
        .datapath
        .as_ref()
        .filter(|value| value.backend == Backend::Xdp)
    else {
        return Ok(());
    };
    datapath.validate()?;
    ensure!(
        datapath.host.is_none() || cfg!(feature = "ebpf"),
        "XDP Host capture requires the built ebpf feature and actual Host runtime admission"
    );
    ensure!(
        !config.global.nfqueue_enable,
        "XDP requires global.nfqueue_enable: false; NFQUEUE is not an XDP fallback"
    );
    ensure!(
        config.global.lan_interface.is_empty() && config.global.wan_interface.is_empty(),
        "XDP interfaces and trusted LAN/WAN roles belong only in datapath.interface"
    );
    ensure!(
        config.routing.default_mark.unwrap_or(0) == 0
            && config
                .routing
                .rules
                .iter()
                .all(|rule| rule.mark.unwrap_or(0) == 0),
        "XDP cannot execute traffic mark effects"
    );
    let security_conditions = datapath
        .firewall
        .iter()
        .flat_map(|firewall| {
            firewall
                .original
                .rules
                .iter()
                .chain(&firewall.forward.rules)
                .map(|rule| &rule.condition)
        })
        .chain(datapath.nat.prerouting.iter().map(|rule| &rule.condition))
        .chain(datapath.nat.postrouting.iter().map(|rule| &rule.condition));
    for condition in security_conditions {
        ensure!(
            condition.mac.is_empty()
                && condition.not.mac.is_empty()
                && condition.process_name.is_empty()
                && condition.not.process_name.is_empty(),
            "XDP firewall/NAT cannot bind process or original-datagram MAC facts across reassembly"
        );
    }
    if datapath.direct == Some(DirectProfile::Core) {
        ensure!(
            config.global.dial_mode == "ip",
            "Core Direct requires dial_mode: ip; TCP termination is not a Core forwarding fallback"
        );
    }
    Ok(())
}

#[cold]
pub(super) fn device_sizing(mtu: u32) -> (PortConfig, usize) {
    queue_sizing(mtu, 0, 0)
}

#[cold]
pub(super) fn queue_sizing(
    mtu: u32,
    eligible_queues: usize,
    remaining: usize,
) -> (PortConfig, usize) {
    const RX_TIER: usize = 512;
    // Two VLAN tags bound TX extent; RX keeps its independent SG admission.
    let single_frame = usize::try_from(mtu)
        .ok()
        .and_then(|mtu| mtu.checked_add(22))
        .is_some_and(|length| length <= FRAME_SIZE);
    // Leave the stack half untouched and screen for UMEM plus per-queue bookkeeping.
    // The real reservations in Port::open_device remain authoritative.
    let (rx_frames, bulk_frames, ring_size, scope_bulk_frames) = if !single_frame {
        (256, 224, 256, 128)
    } else if (1..=8).contains(&eligible_queues)
        && remaining.saturating_sub(CAPTURE_MEMORY / 2)
            >= eligible_queues * 2 * (RX_TIER + 32 + 480) * FRAME_SIZE
    {
        (RX_TIER, 480, 1024, CAPTURE_WIDE_BULK_FRAMES)
    } else {
        (256, 480, 512, CAPTURE_WIDE_BULK_FRAMES)
    };
    (
        PortConfig {
            rx_frames,
            control_frames: 32,
            bulk_frames,
            ring_size,
        },
        scope_bulk_frames,
    )
}

pub(super) fn member_admission_issues(
    info: &DeviceInfo,
    port_config: PortConfig,
    requested_mode: Option<BindMode>,
    metadata_len: usize,
    absent: io::Result<bool>,
) -> [Option<(&'static str, String)>; 2] {
    let mode = select_xsk_mode(info, requested_mode, port_config, metadata_len)
        .err()
        .map(|error| ("xsk_mode", error.to_string()));
    let attachment = match absent {
        Ok(true) => None,
        Ok(false) => Some((
            "foreign_xdp",
            "XDP interface already has a foreign attachment; explicit operator cleanup is required"
                .into(),
        )),
        Err(error) => Some(("xdp_readback", error.to_string())),
    };
    [mode, attachment]
}

pub(super) fn layout_admission_issues(error: &io::Error) -> [(&'static str, String); 2] {
    [
        ("capture_layout", error.to_string()),
        ("NOT_CHECKED", "member mode, foreign XDP, workers, logical MTU, uplink and topology checks depend on capture_layout".into()),
    ]
}

pub(super) fn admission_failure(
    issues: &[(&'static str, String, String)],
    omitted: usize,
) -> String {
    use std::fmt::Write as _;
    let mut message = String::from("XDP startup admission failed");
    for (reason, device, details) in issues {
        let _ = write!(message, "\nreason={reason} device={device}: {details}");
    }
    if omitted != 0 {
        let _ = write!(message, "\nomitted={omitted}");
    }
    message
}

pub(super) fn gateway_time_namespace_issue(
    offset: anyhow::Result<Option<i128>>,
) -> Option<(&'static str, String)> {
    let details = match offset {
        Ok(None | Some(0)) => return None,
        Ok(Some(offset)) => format!("nonzero monotonic namespace offset: {offset} ns"),
        Err(error) => format!("{error:#}"),
    };
    Some(("time_namespace_offset", details))
}

pub(super) fn realm_worker_count(workers: usize, queues: impl Iterator<Item = usize>) -> usize {
    workers.min(queues.min().unwrap_or(0))
}

pub(super) fn direct_relay_eligible(
    direct: Option<DirectProfile>,
    workers: u8,
    owners: usize,
    members: usize,
    physical: bool,
) -> bool {
    direct == Some(DirectProfile::Endpoint)
        && (1..=2).contains(&workers)
        && owners == usize::from(workers)
        && members == 1
        && physical
}

pub(super) async fn prepare(
    plane: &ControlPlane,
    config: &Config,
    admission: Arc<AtomicBool>,
) -> anyhow::Result<PreparedRuntime> {
    let datapath = config
        .datapath
        .as_ref()
        .context("XDP configuration missing")?;
    let mut issues: Vec<(&'static str, String, String)> = Vec::with_capacity(256);
    let mut omitted = 0usize;
    let mut record = |reason: &'static str, device: &str, details: String| {
        if issues.len() < 256 {
            issues.push((reason, device.to_owned(), details));
        } else {
            omitted += 1;
        }
    };
    if let Err(error) = validate_config(config) {
        record("configuration", "capture", format!("{error:#}"));
    }
    let metadata_len = METADATA_LEN;
    let requested_mode = match datapath.effective_xsk_mode() {
        XskMode::Auto => None,
        XskMode::Copy => Some(BindMode::Copy),
        XskMode::ZeroCopy => Some(BindMode::ZeroCopy),
    };
    let plan = match CapturePlan::discover(&datapath.interfaces) {
        Ok(plan) => Some(plan),
        Err(error) => {
            for (reason, details) in layout_admission_issues(&error) {
                record(reason, "capture", details);
            }
            None
        }
    };
    let auxiliary_interfaces = || {
        datapath
            .interfaces
            .iter()
            .filter(|port| port.role == honk_config::datapath::InterfaceRole::L3Lan)
    };
    let lan_count = auxiliary_interfaces().count();
    let host_ports = datapath
        .host
        .as_ref()
        .map_or(&[][..], |host| host.interfaces.as_slice());
    let has_host = !host_ports.is_empty();
    let aux_count = lan_count + host_ports.len();
    let gateway_enabled = datapath.direct == Some(DirectProfile::Endpoint)
        && (has_host || !datapath.interfaces.is_empty());
    if gateway_enabled
        && let Some((reason, details)) =
            gateway_time_namespace_issue(timens::monotonic_namespace_offset())
    {
        record(reason, "namespace", details);
    }
    let budget = MemoryBudget::new(CAPTURE_MEMORY);
    let dns_projection = datapath.effective_dns_projection();
    let mut zones = if gateway_enabled {
        match ZoneAdmission::read(&budget, dns_projection) {
            Ok(zones) => Some(zones),
            Err(error) => {
                record("conntrack_zones", "namespace", error.to_string());
                None
            }
        }
    } else {
        None
    };
    let conntrack = if gateway_enabled && plan.as_ref().is_some_and(|p| !p.members().is_empty()) {
        match honk_xsk::ConntrackKfuncs::read() {
            Ok(conntrack) => Some(Arc::new(conntrack)),
            Err(error) => {
                record("conntrack_btf", "namespace", error.to_string());
                None
            }
        }
    } else {
        None
    };
    let infos: Vec<_> = plan
        .as_ref()
        .map(|plan| {
            plan.members()
                .iter()
                .map(|member| member.info.clone())
                .collect()
        })
        .unwrap_or_default();
    let eligible_queues = match infos.as_slice() {
        [device]
            if gateway_enabled
                && requested_mode == Some(BindMode::ZeroCopy)
                && plan.as_ref().is_some_and(|plan| plan.realms().len() == 1) =>
        {
            device.queues.len()
        }
        _ => 0,
    };
    let physical_config = |mtu| {
        queue_sizing(
            mtu,
            eligible_queues,
            budget.limit().saturating_sub(budget.used()),
        )
        .0
    };
    let topology = if let Some(plan) = &plan {
        if gateway_enabled
            && !plan.members().is_empty()
            && let Err(error) = plan.check_gateway_defaults()
        {
            record("gateway_uplink", "namespace", error.to_string());
        }
        if let Err(error) = worker::admit(datapath.effective_workers(), &infos) {
            record("workers", "capture", format!("{error:#}"));
        }
        for info in &infos {
            for (reason, details) in member_admission_issues(
                info,
                physical_config(info.mtu),
                requested_mode,
                metadata_len,
                honk_xsk::xdp_absent(info.ifindex),
            )
            .into_iter()
            .flatten()
            {
                record(reason, &info.name, details);
            }
        }
        for realm in plan.realms().iter().filter(|realm| realm.mtu < 1280) {
            record(
                "logical_mtu",
                &realm.name,
                "logical MTU must be at least 1280".into(),
            );
        }
        match CaptureTopology::admit(plan, &budget) {
            Ok(topology) => Some(topology),
            Err(error) => {
                record("capture_topology", "capture", error.to_string());
                None
            }
        }
    } else {
        None
    };
    let realm_count = plan.as_ref().map_or(0, |plan| plan.realms().len());
    if plan.is_some() && !(1..=64).contains(&(realm_count + aux_count)) {
        record(
            "realm_capacity",
            "capture",
            "logical capture realm capacity exceeded".into(),
        );
    }
    let plan_memory = if let Some(plan) = &plan {
        match budget.reserve(plan.memory_bytes()) {
            Some(memory) => Some(memory),
            None => {
                record(
                    "capture_budget",
                    "capture",
                    "capture plan memory capacity".into(),
                );
                None
            }
        }
    } else {
        None
    };
    let extent = infos
        .iter()
        .map(|info| info.mtu as usize + 22 + metadata_len)
        .max()
        .unwrap_or(65536);
    let workers = if plan.is_some() {
        match worker::Shared::new(
            datapath.effective_workers(),
            extent,
            infos.iter().map(|info| info.queues.len()).sum(),
            &budget,
            Arc::clone(&admission),
        ) {
            Ok(workers) => Some(workers),
            Err(error) => {
                record(
                    "capture_budget",
                    "capture",
                    format!("worker handoff: {error:#}"),
                );
                None
            }
        }
    } else {
        None
    };
    let fib = (|| -> anyhow::Result<_> {
        let namespace = if has_host {
            crate::control::probe_socket_marks(config.global.effective_so_mark())?
        } else {
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
            socket_namespace(socket.as_fd())?
        };
        let mut links = Fib::new(&budget, namespace)?;
        links.synchronize()?;
        Ok((namespace, links))
    })();
    if let Err(error) = &fib {
        record("local_addresses", "namespace", format!("{error:#}"));
    }
    let max_mtu = infos.iter().map(|info| info.mtu).max().unwrap_or(65535) as usize;
    let memory = if plan.is_some() {
        let bytes = max_mtu
            + 65536
            + size_of::<Runtime>()
            + size_of::<CaptureTopology>()
            + aux_count
                * (size_of::<tcx_aux::PreparedAux>()
                    + size_of::<(PacketRealm, Vec<crate::control::netstack::PacketOwner>)>())
            + PENDING * (size_of::<Waiting>() + size_of::<Pending>())
            + realm_count
                * usize::from(datapath.effective_workers())
                * (size_of::<Realm>()
                    + size_of::<RealmPlan>()
                    + size_of::<PacketDriver>()
                    + size_of::<(PacketScope, crate::control::netstack::PacketOwner)>()
                    + size_of::<Ingress>()
                    + size_of::<IngressBinding>())
            + infos.len() * size_of::<Device>()
            + infos
                .iter()
                .map(|info| {
                    info.queues.len() * size_of::<Queue>()
                        + info.name.capacity()
                        + (info.queues.capacity() + info.upper_ifindices.capacity())
                            * size_of::<u32>()
                })
                .sum::<usize>();
        match budget.reserve(bytes) {
            Some(memory) => Some(memory),
            None => {
                record(
                    "capture_budget",
                    "capture",
                    "metadata and staging memory capacity".into(),
                );
                None
            }
        }
    } else {
        None
    };
    if !issues.is_empty() {
        anyhow::bail!(admission_failure(&issues, omitted));
    }
    let plan = plan.context("capture layout was not checked")?;
    let plan_memory = plan_memory.context("capture plan budget was not checked")?;
    let memory = memory.context("capture metadata budget was not checked")?;
    let (workers, inboxes) = workers.context("capture workers were not checked")?;
    let realm_keys = plan.realm_keys();
    let mut placements = worker::Placements::new(realm_keys.len(), &budget)?;
    let (namespace, links) = fib?;
    let topology = topology.context("capture topology was not checked")?;
    // SAFETY: the watcher keeps its descriptor until AsyncFd drops it.
    let topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
    let polling_prefix = ContextDigest::platform(&budget);
    tracing::debug!(
        used = budget.used(),
        limit = budget.limit(),
        realm_count,
        "XDP prepare: after metadata reservation"
    );
    let routing_scope = ScopeId::allocate().context("XDP routing domain exhausted")?;
    let mut realms = Vec::with_capacity(realm_count);
    let mut scope_pairs = Vec::with_capacity(realm_count + aux_count);
    let mut auxiliary = Vec::with_capacity(aux_count);
    if aux_count != 0 {
        ensure!(
            realm_keys.len() + aux_count
                <= honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY as usize,
            "physical and auxiliary capture keys exceed the gateway realm table"
        );
        let private_names = (0..lan_count)
            .map(tcx_aux::PreparedAux::device_name)
            .chain((0..host_ports.len()).map(tcx_aux::PreparedAux::host_device_name));
        for name in private_names {
            ensure!(
                datapath.interfaces.iter().all(|port| port.name != name)
                    && !host_ports.contains(&name),
                "configured interface {name} collides with a private TUN"
            );
        }
        let tasks = aux_tasks::AuxTasks::reserve(aux_count, &budget, plane.shutdown_intent())?;
        assert!(workers.auxiliary.set(tasks).is_ok());
        for (index, port) in auxiliary_interfaces().enumerate() {
            let id = u32::try_from(plan.realms().len() + index + 1)?;
            let (aux, scope, owner) = tcx_aux::PreparedAux::new(&port.name, id, index, &budget)?;
            let realm = PacketRealm::singleton(scope)?;
            scope_pairs.push((realm, vec![owner]));
            auxiliary.push(aux);
        }
        for (index, name) in host_ports.iter().enumerate() {
            let id = u32::try_from(realm_count + lan_count + index + 1)?;
            let (aux, scope, owner) = tcx_aux::PreparedAux::new_host(
                name,
                id,
                index,
                datapath.interfaces.iter().map(|p| p.name.as_str()),
                &budget,
            )?;
            scope_pairs.push((PacketRealm::singleton(scope)?, vec![owner]));
            auxiliary.push(aux);
        }
    }
    let config_generation = plane.diagnostics_handle().read().generation;
    let authority = if datapath.direct == Some(DirectProfile::Core) {
        Some(plane.core_forward_policy(Execution::MixedEndpoints).await?)
    } else {
        None
    };
    let policy = if gateway_enabled {
        let policy = GatewayPolicy::prepare(
            &plane.active_routing_plan_handle().read().plan,
            false,
            has_host.then_some(false),
        )?;
        let charge = gateway::reserve_objects(&budget, policy.fact_fds())?;
        Some((policy, charge))
    } else {
        None
    };
    let mut local_addresses: Vec<_> = links.local_addresses().map(LocalAddressKey::from).collect();
    local_addresses.sort_unstable_by_key(|key| (key.family, key.address));
    local_addresses.dedup();
    let gateway_maps = if policy.is_some() {
        let maps = if auxiliary.is_empty() {
            honk_xsk::GatewayMaps::new(&realm_keys, &local_addresses)?
        } else {
            let mut lans = [0; honk_config::datapath::MAX_L3_LANS];
            let mut hosts = [0; 4];
            for (id, aux) in lans.iter_mut().zip(&auxiliary[..lan_count]) {
                *id = aux.realm();
            }
            for (id, aux) in hosts.iter_mut().zip(&auxiliary[lan_count..]) {
                *id = aux.realm();
            }
            honk_xsk::GatewayMaps::new_with_host(
                &realm_keys,
                &local_addresses,
                &lans[..lan_count],
                &hosts[..host_ports.len()],
            )?
        };
        Some(Arc::new(maps.account(&budget)?))
    } else {
        None
    };
    let mut kernel_memory = Vec::new();
    let mut local_memory = None;
    if let Some(maps) = &gateway_maps {
        let backend = plane.policy_backend_handle();
        maps.set_mode_flags(backend.write().await.userspace_mut()?.mode_flags())?;
        local_memory = Some(
            budget
                .reserve(honk_xsk::kernel_memory_bytes(maps.local_map_fd()?.as_fd())?)
                .context("gateway local map memory capacity")?,
        );
    }
    if let Some(zones) = &mut zones {
        zones.revalidate(&budget)?;
    }
    let dns_bind = if has_host {
        PacketEndpoints::prepare_dns_bind(config)?
    } else {
        None
    };
    let host_scope = has_host
        .then(|| ScopeId::allocate().context("Host DNS scope exhausted"))
        .transpose()?;
    let standalone_dns_scope = if has_host {
        ScopeId::allocate().context("standalone DNS scope exhausted")?
    } else {
        ScopeId::HOST
    };
    #[cfg(feature = "ebpf")]
    let (host_resources, source_support) = if has_host {
        let needs_pname = plane.active_routing_plan_handle().read().plan.features
            & honk_ebpf_common::ROUTING_FEATURE_PROCESS
            != 0;
        let identity = host_identity::HostIdentity::load(&budget, needs_pname)?;
        let support = identity.pname_support();
        let resources =
            gateway::HostResources::prepare(identity, config.global.effective_so_mark(), &budget)?;
        (Some(resources), support)
    } else {
        (None, crate::ebpf::PnameSupport::Unavailable)
    };
    #[cfg(not(feature = "ebpf"))]
    let source_support = crate::ebpf::PnameSupport::Unavailable;
    let mut devices = StartupDevices(Vec::with_capacity(infos.len()));
    for (device_index, info) in infos.into_iter().enumerate() {
        let port_config = physical_config(info.mtu);
        let binding_mode = select_xsk_mode(&info, requested_mode, port_config, metadata_len)?;
        let vlan_offload = prepare_vlan_offload(&info, &budget)?;
        // A device without a complete feature identity (virtio reports no firmware version)
        // only stays ineligible for busy polling; each polling context rebuild queries it again.
        let features = FeatureQuery::new(&info, &budget).ok();
        let incarnation = ScopeId::allocate()
            .context("XDP attachment identity exhausted")?
            .as_u64();
        let capture = GeneralCapture {
            authority: CaptureAuthority {
                namespace_cookie: namespace,
                attachment_generation: incarnation,
                scope: routing_scope.as_u64(),
                config_generation,
                ifindex: info.ifindex,
                reserved: 0,
            },
            bypass_mark: config.global.effective_so_mark(),
            vlan_metadata: info.vlan_metadata,
        };
        let queues = info
            .queues
            .last()
            .copied()
            .context("XDP device has no RX queues")?
            .checked_add(1)
            .context("XDP queue identity overflow")?;
        let programs = if let (Some((policy, _)), Some(maps), Some(ct)) =
            (&policy, &gateway_maps, &conntrack)
        {
            Programs::load_general_gateway(
                &capture,
                queues,
                topology.get_ref().ipv4_broadcasts(),
                honk_xsk::GatewayLoad {
                    routing: &policy.bytecode.insns,
                    maps,
                    conntrack: Some(ct),
                    dns: None,
                    arbitration: None,
                },
            )?
        } else {
            Programs::load_general(&capture, queues, topology.get_ref().ipv4_broadcasts())?
        };
        let objects = programs.object_fds();
        kernel_memory.push(gateway::reserve_objects(
            &budget,
            objects[..2].iter().copied(),
        )?);
        let program_memory = gateway::reserve_objects(&budget, objects[2..].iter().copied())?;
        let attachment = OwnedXdpLink::create(info.ifindex, programs.discover_fd())?;
        let ports =
            info.open_ports::<Retained>(binding_mode, port_config, metadata_len, &budget)?;
        ensure!(
            ports
                .iter()
                .all(|port| socket_namespace(port.as_fd())
                    .is_ok_and(|observed| observed == namespace)),
            "queue capture namespace changed"
        );
        let mut queues = Vec::with_capacity(ports.len());
        for (id, mut port) in info.queues.iter().copied().zip(ports) {
            port.refill()?;
            programs.insert_xsk(id, port.as_fd())?;
            let zero_copy = port.zerocopy();
            let observed = port.counters();
            let observed_rings = port.rings();
            let io = if id % u32::from(datapath.effective_workers()) == 0 {
                let (io, registered) = QueueIo::Prepared(port).register();
                registered?;
                io
            } else {
                QueueIo::Prepared(port)
            };
            queues.push(Queue {
                id,
                observed,
                observed_rings,
                io,
            });
            tracing::info!(interface = %info.name, ifindex = info.ifindex, queue = id, zero_copy, vlan_metadata = capture.vlan_metadata, "XDP queue bound");
        }
        devices.push(Device {
            info: Arc::new(info),
            capture,
            queue_maps: Arc::clone(programs.queue_maps()),
            programs: Some((programs, program_memory)),
            attachment: Some(attachment),
            vlan_offload,
            queues,
            active: false,
            metadata_checked: Instant::now(),
            features,
            port_config,
            role: plan
                .realms()
                .iter()
                .find(|realm| realm.realm_id == plan.members()[device_index].realm_id)
                .context("capture member role missing")?
                .role,
        });
    }
    let mut realm_scopes = std::collections::HashMap::new();
    for logical in plan.realms() {
        let members: Vec<_> = devices
            .iter()
            .enumerate()
            .filter(|(_, device)| {
                realm_keys.iter().any(|(key, id)| {
                    *id == logical.realm_id && key.physical_ifindex == device.info.ifindex
                })
            })
            .map(|(index, _)| index)
            .collect();
        let device_index = *members
            .first()
            .context("logical capture realm has no physical member")?;
        let device = &devices[device_index];
        let (_, scope_bulk_frames) = device_sizing(device.info.mtu);
        let link = LogicalLink {
            ifindex: logical.logical_ifindex,
            mtu: logical.mtu,
            mac: logical.mac,
            path: LinkPath {
                physical_ifindex: device.info.ifindex,
                vlan_tci: logical.vid,
                vlan_proto: logical.tpid,
                vlan_count: u8::try_from(logical.vlan_count)?,
            },
        };
        let ingress = Ingress {
            scope: routing_scope,
            namespace,
            ifindex: link.ifindex,
            attachment: device.capture.authority.attachment_generation,
            mark: MarkProvenance::BeforeSkb,
        };
        let worker_count = realm_worker_count(
            usize::from(datapath.effective_workers()),
            members
                .iter()
                .map(|index| devices[*index].info.queues.len()),
        );
        let (realm, owners) = capture_realm(
            link.mtu,
            realm_count,
            scope_bulk_frames,
            worker_count,
            members.len(),
            &budget,
        )?;
        realm.install_admission_fence(Arc::clone(&admission))?;
        realm_scopes.insert(logical.realm_id, realm.scope());
        realms.push((ingress, device_index, link, realm.scope()));
        for member in members {
            let mut member_link = link;
            member_link.path.physical_ifindex = devices[member].info.ifindex;
            placements.entries.push(worker::Placement {
                realm_id: logical.realm_id,
                realm: realm.clone(),
                ingress,
                device: member,
                link: member_link,
            });
        }
        scope_pairs.push((realm, owners));
    }
    // Reserve auxiliary memory first, but keep physical owners first in the ingress lookup.
    scope_pairs.rotate_left(auxiliary.len());
    for aux in &auxiliary {
        realm_scopes.insert(aux.realm(), aux.scope());
    }
    // Worker 1 takes its immutable reference before registering its queues.
    assert!(workers.placements.set(Arc::new(placements)).is_ok());
    let diagnostics = diagnostics(&devices, &budget)?;
    workers
        .diagnostics
        .set(Arc::clone(&diagnostics))
        .expect("one diagnostics owner per capture");
    tracing::debug!(used = budget.used(), "XDP prepare: after diagnostics");
    let ingresses: Vec<_> = realms.iter().map(|(ingress, ..)| *ingress).collect();
    let core = if let Some(authority) = authority {
        let mut core = RoutedCore::new(
            authority,
            &ingresses,
            Requirements {
                execution: Execution::MixedEndpoints,
                nat: !datapath.nat.is_empty(),
                native_continuation: false,
                kernel_firewall: false,
                qdisc: false,
                skb_classification: false,
            },
            Arc::clone(&budget),
        )?;
        let bindings: Vec<_> = realms
            .iter()
            .map(|(ingress, device, _, facts)| IngressBinding {
                ingress: *ingress,
                role: devices[*device].role,
                facts: *facts,
            })
            .collect();
        core.set_ingress_bindings(&bindings)?;
        core.prepare_fragment_peers()?;
        Some(core)
    } else {
        None
    };
    let gateway = match (policy, gateway_maps.as_ref()) {
        (Some(policy), Some(maps)) => {
            let lan =
                plan.realms()
                    .iter()
                    .filter(|realm| {
                        dns_projection && realm.role == honk_config::datapath::InterfaceRole::Lan
                    })
                    .map(|realm| (realm_scopes[&realm.realm_id], realm.realm_id))
                    .chain(
                        auxiliary
                            .iter()
                            .filter(|aux| dns_projection && !aux.is_host())
                            .map(|aux| (aux.scope(), aux.realm())),
                    )
                    .chain(host_scope.filter(|_| dns_projection).map(|scope| {
                        (scope, honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY)
                    }));
            let shadow = gateway::GatewayShadow::new(
                lan,
                plane,
                Arc::clone(&diagnostics),
                Arc::clone(&admission),
                &budget,
                zones.as_ref().is_some_and(ZoneAdmission::notrack_seen),
            );
            let mut publisher = GatewayPublisher::new(
                policy,
                Arc::clone(maps),
                conntrack,
                Arc::clone(&budget),
                shadow,
                plane.active_routing_plan_handle(),
            );
            if lan_count != 0 {
                publisher.prepare_auxiliary(lan_count)?;
            }
            #[cfg(feature = "ebpf")]
            if let Some(resources) = host_resources {
                publisher.prepare_host(resources)?;
            }
            Some(Arc::new(publisher))
        }
        _ => None,
    };
    let projection = plane.packet_routing_projection();
    if lan_count != 0 {
        let mut scopes = [ScopeId::HOST; honk_config::datapath::MAX_L3_LANS];
        for (scope, aux) in scopes.iter_mut().zip(&auxiliary[..lan_count]) {
            *scope = aux.scope();
        }
        projection.register_aux_scopes(&scopes[..lan_count], &budget)?;
    }
    if let Some(shared) = host_scope {
        let mut ports = Vec::with_capacity(host_ports.len());
        for (realm, _) in &scope_pairs[realm_count + lan_count..] {
            ports.push(realm.owners()[0].clone());
        }
        projection.register_host_scopes(shared, standalone_dns_scope, &ports, &budget)?;
    }
    Ok(PreparedRuntime {
        devices: std::mem::take(&mut devices.0),
        topology,
        capture_plan: plan,
        plan_memory,
        gateway,
        gateway_maps,
        zones,
        local_addresses,
        local_memory,
        kernel_memory,
        realm_scopes,
        auxiliary,
        dns_bind,
        standalone_dns_scope,
        source_support,
        realms,
        scope_pairs,
        workers,
        inboxes,
        core,
        memory,
        staging: vec![0; max_mtu.max(65536)],
        links,
        polling_prefix,
        polling_budget: budget,
        diagnostics,
    })
}
