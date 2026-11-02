use super::*;
use anyhow::Context as _;

struct StartupPins<'a> {
    root: &'a Path,
    names: Vec<String>,
}

impl Drop for StartupPins<'_> {
    fn drop(&mut self) {
        for name in &self.names {
            if let Err(error) = std::fs::remove_file(self.root.join(name))
                && error.kind() != std::io::ErrorKind::NotFound
            {
                debug!(map = name, %error, "remove failed-start eBPF map pin");
            }
        }
    }
}

impl RealEbpfBackend {
    /// `local_ip` is the IPv4 (`u32::from_ne_bytes` of the octets) of the first
    /// resolved LAN, else WAN, interface; 0 when it has none. No configured
    /// interface is attached here: `bind_interfaces` does that.
    pub async fn load(
        obj: &[u8],
        pin_root: &Path,
        tproxy_port: u16,
        dae0: &crate::daens::Dae0Setup,
        local_ip: u32,
    ) -> anyhow::Result<Self> {
        let version =
            kernel_version().ok_or_else(|| anyhow::anyhow!("cannot determine kernel version"))?;
        anyhow::ensure!(
            version >= (6, 12, 0),
            "compiled routing requires Linux 6.12 or newer (running {}.{}.{})",
            version.0,
            version.1,
            version.2
        );
        layout::validate_object(obj)?;
        let (kernel_data, kernel_btf) = btf::load_kernel()?;
        let process_name_offsets = process_name::detect(&kernel_data);
        let pname_mode = process_name::select_capture_mode(obj, &kernel_btf, process_name_offsets);
        let tcp_daens_netns_id = crate::daens::daens_netns_id()?;
        let tcp_daens_netns_cookie = crate::daens::daens_netns_cookie()?;
        let ipv6_sockets_available =
            u8::from(crate::netlink::ipv6_socket_available().context("probe IPv6 socket family")?);

        info!("Loading eBPF programs ({} bytes)", obj.len());
        let (dae0_ifindex, dae0peer_ifindex, dae0peer_mac) =
            (dae0.ifindex(), dae0.peer_ifindex(), dae0.peer_mac());
        let wan_ifindex = 0u32;
        // Enable bpf_redirect_peer on kernels >= 6.8, and also on backported
        // LTS kernels that received the CVE-2024-37959 fix:
        //   5.15.164+, 6.1.99+, 6.6.40+
        // https://www.kernel.org/doc/Documentation/networking/netkit.rst
        let use_redirect_peer = match kernel_version() {
            Some((major, minor, patch)) => {
                let enabled = (major > 6 || (major == 6 && minor >= 8))   // >= 6.8
                    || (major == 5 && minor == 15 && patch >= 164)        // >= 5.15.164
                    || (major == 6 && minor == 1 && patch >= 99)          // >= 6.1.99
                    || (major == 6 && minor == 6 && patch >= 40); // >= 6.6.40
                if enabled {
                    info!(
                        "Kernel {}.{}.{} supports bpf_redirect_peer, enabling",
                        major, minor, patch
                    );
                    1u8
                } else {
                    info!(
                        "Kernel {}.{}.{} does not support bpf_redirect_peer, disabled",
                        major, minor, patch
                    );
                    0u8
                }
            }
            None => {
                warn!(
                    "Could not determine kernel version; bpf_redirect_peer disabled (safe default)"
                );
                0u8
            }
        };

        let dae_param = DaeParam {
            tproxy_port: tproxy_port.to_be() as u32,
            dae0_ifindex,
            wan_ifindex,
            dae0peer_mac,
            use_redirect_peer,
            has_bpf_get_current_task: matches!(pname_mode, process_name::PnameCaptureMode::Argv0)
                as u8,
            dae_socket_mark: honk_outbound::util::bypass_mark(),
            control_plane_pid: std::process::id(),
            tcp_daens_netns_id,
            local_ip,
            ..Default::default()
        };
        debug!(
            "PARAM: port={} dae0_ifindex={} local_ip={:#x}",
            tproxy_port, dae0_ifindex, local_ip
        );
        std::fs::create_dir_all(pin_root)?;
        let sequence_pin = pin_root.join(UDP_DECISION_SEQUENCE_MAP);
        if sequence_pin.try_exists()? {
            syscall::validate_pinned_udp_decision_sequence(&sequence_pin)?;
        }
        let routing_generation_sequence = routing::open_routing_generation_sequence(
            &pin_root.join(routing::ROUTING_GENERATION_SEQUENCE_MAP),
        )?;

        // A stale pin must never hide a generation-owned map. Persistent
        // allocators are opened separately because generation reuse is forbidden.
        let _ = std::fs::remove_file(pin_root.join("LISTEN_SOCKET_MAP"));
        let mut loader = EbpfLoader::new();
        loader
            .btf(&kernel_btf)
            .override_global("PARAM", &dae_param, true)
            .override_global("WAN_IFINDEX", &wan_ifindex, true)
            .override_global("DAE0PEER_IFINDEX", &dae0peer_ifindex, true)
            .override_global("TCP_DAENS_NETNS_COOKIE", &tcp_daens_netns_cookie, true)
            .override_global("IPV6_SOCKETS_AVAILABLE", &ipv6_sockets_available, true)
            .map_pin_path(UDP_DECISION_SEQUENCE_MAP, sequence_pin.as_path());
        if matches!(pname_mode, process_name::PnameCaptureMode::Argv0)
            && let Some(offsets) = process_name_offsets.as_ref()
        {
            loader
                .override_global("TASK_MM_OFFSET", &offsets.task_mm, true)
                .override_global("MM_ARG_START_OFFSET", &offsets.mm_arg_start, true);
        }
        #[cfg(feature = "native-api")]
        let receive_trace_offsets = receive_trace::detect(&kernel_data);
        #[cfg(feature = "native-api")]
        if let Some(offsets) = &receive_trace_offsets {
            offsets.configure(&mut loader);
        }
        let mut bpf = loader.load(obj)?;
        layout::validate_loaded_maps(&bpf)?;
        layout::validate_socket_identity(&bpf)?;
        syscall::validate_loaded_udp_decision_sequence(&bpf)?;
        for name in [
            "COOKIE_PID_MAP",
            "UDP_DECISION_EPOCH",
            "UDP_DECISION_INFLIGHT",
            "UDP_DECISION_RETIRE_FENCE",
            "TCP_REQUEST_BINDINGS",
            "REQUEST_FENCE",
        ] {
            if let Err(error) = std::fs::remove_file(pin_root.join(name))
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(anyhow::Error::new(error)
                    .context(format!("remove obsolete eBPF map pin {name}")));
            }
        }
        let retirement_grace_inner = retirement::init_retirement_grace(&mut bpf)?;
        let mut pinned_maps = StartupPins {
            root: pin_root,
            names: Vec::new(),
        };
        for (name, map) in bpf.maps() {
            // aya exposes ELF internal sections (.rodata, .bss, etc.) as maps.
            // These cannot be pinned to bpffs; skip them to avoid noisy warnings.
            if name.starts_with('.') {
                debug!("skipping internal map '{}'", name);
                continue;
            }
            if name == UDP_DECISION_SEQUENCE_MAP || name == routing::ROUTING_GENERATION_SEQUENCE_MAP
            {
                continue;
            }
            let pin_path = pin_root.join(name);
            if let Err(error) = std::fs::remove_file(&pin_path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                debug!("remove stale pin '{}': {}", name, error);
            }
            if let Err(e) = map.pin(&pin_path) {
                warn!("pin '{}': {}", name, e);
            } else {
                // Only successful new pins belong to this attempt; failed replacement leaves
                // a pre-existing pin owned by someone else.
                pinned_maps.names.push(name.to_owned());
                debug!("pinned '{}'", name);
            }
        }
        let event_map = bpf
            .take_map("EVENT_RINGBUF")
            .ok_or_else(|| anyhow::anyhow!("required EVENT_RINGBUF map not found"))?;
        let event_ring = aya::maps::RingBuf::try_from(event_map)
            .map_err(|error| anyhow::anyhow!("required EVENT_RINGBUF open: {error}"))?;
        let event_fd = unsafe {
            tokio::io::unix::AsyncFd::register_with_interest(
                event_ring,
                tokio::io::Interest::READABLE,
            )
        }
        .map_err(|error| anyhow::anyhow!("required EVENT_RINGBUF AsyncFd setup: {error}"))?;
        match pname_mode {
            process_name::PnameCaptureMode::Argv0 => {
                info!("process-name routing uses argv[0] basename")
            }
            process_name::PnameCaptureMode::Comm => {
                warn!("kernel argv capture unavailable; using thread comm")
            }
        }
        // Required socket-lifetime identity capture. Keep every link owned by
        // the backend; missing support or a partial attachment is fatal.
        let mut cgroup_sock_links = Vec::new();
        let mut cgroup_sock_addr_links = Vec::new();
        let cgroup_path = detect_cgroup_path()
            .map_err(|error| anyhow::anyhow!("required socket identity capture: {error}"))?;
        let cgroup_file = std::fs::File::open(&cgroup_path)
            .map_err(|e| anyhow::anyhow!("open cgroup {}: {}", cgroup_path, e))?;
        let (create_name, cg_addr_names) = match pname_mode {
            process_name::PnameCaptureMode::Argv0 => (
                "tproxy_wan_cg_sock_create",
                [
                    "tproxy_wan_cg_connect4",
                    "tproxy_wan_cg_connect6",
                    "tproxy_wan_cg_sendmsg4",
                    "tproxy_wan_cg_sendmsg6",
                ],
            ),
            process_name::PnameCaptureMode::Comm => (
                "tproxy_wan_cg_sock_create_comm",
                [
                    "tproxy_wan_cg_connect4_comm",
                    "tproxy_wan_cg_connect6_comm",
                    "tproxy_wan_cg_sendmsg4_comm",
                    "tproxy_wan_cg_sendmsg6_comm",
                ],
            ),
        };
        let p: &mut aya::programs::CgroupSock = bpf
            .program_mut(create_name)
            .and_then(|p| p.try_into().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("required socket identity program {} not found", create_name)
            })?;
        p.load().map_err(|error| {
            anyhow::anyhow!("required socket identity program {create_name} load: {error}")
        })?;
        let link_id = p
            .attach(&cgroup_file, aya::programs::CgroupAttachMode::Single)
            .map_err(|error| {
                anyhow::anyhow!("required socket identity program {create_name} attach: {error}")
            })?;
        cgroup_sock_links.push(p.take_link(link_id)?);
        for name in &cg_addr_names {
            let p: &mut aya::programs::CgroupSockAddr = bpf
                .program_mut(name)
                .and_then(|p| p.try_into().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("required socket identity program {} not found", name)
                })?;
            p.load().map_err(|error| {
                anyhow::anyhow!("required socket identity program {name} load: {error}")
            })?;
            let link_id = p
                .attach(&cgroup_file, aya::programs::CgroupAttachMode::Single)
                .map_err(|error| {
                    anyhow::anyhow!("required socket identity program {name} attach: {error}")
                })?;
            cgroup_sock_addr_links.push(p.take_link(link_id)?);
        }
        let tcp_proof_link = tcp_binding::attach(&mut bpf, &cgroup_file)?;
        info!("Attached 6 required cgroup programs to {}", cgroup_path);
        // Initialize outbound connectivity map: all entries are alive by default.
        // This map is updated by health checks; until then we must not drop
        // proxy-bound traffic. Skipping entries here marks every outbound
        // dead, so an insert error aborts startup.
        for index in 0..honk_ebpf_common::MAX_OUTBOUNDS * 6 {
            set_array_value(&mut bpf, "OUTBOUND_CONNECTIVITY_MAP", index, &1u64)
                .map_err(|e| anyhow::anyhow!("OUTBOUND_CONNECTIVITY_MAP init: {e}"))?;
        }

        // Every TC variant is loaded up front, so reconciling interfaces later
        // never runs the verifier. Before `EbpfLogger::init`, which holds the
        // AYA_LOGS map fd the loads need.
        let bindings = bindings::InterfaceBindings::preload(&mut bpf)?;

        info!("eBPF loaded and attached");

        // aya-log must be initialized *after* programs are loaded, otherwise the
        // AYA_LOGS map fd taken by the logger is not valid during BPF_PROG_LOAD.
        //
        // Wait on the ringbuf fd with AsyncFd (official aya-log 0.3 pattern).
        // A fixed-interval flush was waking every 100ms even when empty and
        // could burn a full core under high eBPF log volume via spawn_blocking.
        let log_flush_handle = match aya_log::EbpfLogger::init(&mut bpf) {
            Ok(logger) => {
                debug!("eBPF logger initialized");
                match unsafe {
                    tokio::io::unix::AsyncFd::register_with_interest(
                        logger,
                        tokio::io::Interest::READABLE,
                    )
                } {
                    Ok(async_logger) => Some(tokio::spawn(async move {
                        let mut async_logger = async_logger;
                        loop {
                            let mut guard = match async_logger.readable_mut().await {
                                Ok(g) => g,
                                Err(e) => {
                                    debug!("eBPF logger AsyncFd wait failed: {}", e);
                                    break;
                                }
                            };
                            // Non-blocking drain; returns immediately when empty.
                            guard.get_inner_mut().flush();
                            guard.clear_ready();
                        }
                    })),
                    Err(e) => {
                        warn!(
                            "eBPF logger AsyncFd setup failed (logs will not be drained): {}",
                            e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                debug!(
                    "eBPF logger init failed (no log statements or aya-log mismatch): {}",
                    e
                );
                None
            }
        };
        let (expiry_tx, expiry_rx) = tokio::sync::mpsc::channel(RETIRE_BATCH_CAPACITY);
        let event_flush_handle = Some(tokio::spawn(consume_dae_events(event_fd, expiry_tx)));
        let tcp_live_pins = tcp_binding::take_live_pins(&mut bpf)?;

        Ok(Self {
            bpf: Some(bpf),
            pin_root: pin_root.to_path_buf(),
            pinned_maps: std::mem::take(&mut pinned_maps.names),
            bindings,
            cgroup_sock_links,
            cgroup_sock_addr_links,
            pname_mode,
            dae0_ingress_link: None,
            dae0peer_ingress_link: None,
            sk_lookup_link: None,
            listeners_published: false,
            log_flush_handle,
            event_flush_handle,
            expiry_hints: Some(expiry_rx),
            retirement_grace_inner,
            retirement_owner: 0,
            retirement_failed: false,
            #[cfg(test)]
            retirement_faults: Default::default(),
            tcp_proof_link: Some(tcp_proof_link),
            cap_lookup_batch: BatchCapability::new(),
            cap_flow_lookup_batch: BatchCapability::new(),
            tcp_live_pins,
            routing_generation: None,
            routing_slot: 0,
            routing_generation_counter: 0,
            routing_generation_sequence,
            next_trace_policy: 0,
            #[cfg(feature = "native-api")]
            trace_dictionaries: Default::default(),
            #[cfg(feature = "native-api")]
            receive_trace: None,
            #[cfg(feature = "native-api")]
            receive_trace_available: receive_trace_offsets.is_some(),
            #[cfg(feature = "native-api")]
            receive_trace_attempted: false,
            udp_staging_quiesce_incomplete: false,
            aux_deletes: Default::default(),
        })
    }

    fn attach_tc_at(
        bpf: &mut Ebpf,
        prog: &str,
        iface: &str,
        dir: aya::programs::TcAttachType,
    ) -> anyhow::Result<aya::programs::tc::SchedClassifierLinkId> {
        let p: &mut aya::programs::SchedClassifier = bpf
            .program_mut(prog)
            .ok_or_else(|| anyhow::anyhow!("prog '{}' not found", prog))?
            .try_into()?;
        // The program may already be loaded (`load` preloads the TC variants).
        match p.load() {
            Ok(()) => {}
            Err(aya::programs::ProgramError::AlreadyLoaded) => {}
            Err(e) => return Err(anyhow::anyhow!("load '{}': {}", prog, e)),
        }
        let name = std::ffi::CString::new(iface)
            .map_err(|e| anyhow::anyhow!("interface name '{}': {}", iface, e))?;
        let id = p
            .attach(name.as_c_str(), dir)
            .map_err(|e| anyhow::anyhow!("attach '{}': {} (raw={:?})", prog, e, e))?;
        debug!(
            "attached '{}' to {} ({:?}) link_id={:?}",
            prog, iface, dir, id
        );
        Ok(id)
    }

    pub fn attach_tc(
        bpf: &mut Ebpf,
        prog: &str,
        iface: &str,
    ) -> anyhow::Result<aya::programs::tc::SchedClassifierLinkId> {
        Self::attach_tc_at(bpf, prog, iface, aya::programs::TcAttachType::Ingress)
    }
}
