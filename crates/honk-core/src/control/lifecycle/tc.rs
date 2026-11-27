//! Listener publication and kernel maintenance for a TC-capable backend.

use super::*;

impl ControlPlane {
    pub(super) async fn bind_runtime_listeners(&self) -> anyhow::Result<BoundListeners> {
        TcKernelController::require(&self.tc_kernel)?;
        let config = self.config.read().await;
        let tproxy_port = config.global.tproxy_port;
        let tproxy_mark = config.global.tproxy_mark;
        let udp_nfqueue_enabled = config.global.nfqueue_enable
            && self.ebpf.read().await.observe_datapath().kind == crate::ebpf::DatapathKind::Real;
        let dns_bind_endpoint = config
            .dns
            .bind_endpoint()
            .map_err(|error| anyhow::anyhow!("invalid dns.bind: {error}"))?;
        drop(config);
        #[cfg(feature = "legacy-tc")]
        {
            let _reload = self.reload_lock.lock().await;
            self.warn_lan_self_protection().await;
        }
        let bound_dns_listener = dns_bind_endpoint
            .as_ref()
            .map(|endpoint| dns_listener::BoundDnsListener::bind(endpoint, None))
            .transpose()
            .map_err(|error| anyhow::anyhow!("bind dns.bind listener: {error}"))?;
        let tcp4_addr = SocketAddr::new("0.0.0.0".parse()?, tproxy_port);
        let tcp6_addr = SocketAddr::new("::".parse()?, tproxy_port);
        let udp4_addr = tcp4_addr;
        let udp6_addr = tcp6_addr;

        let tcp4_listener = unsafe {
            tokio::io::unix::AsyncFd::register(bind_tproxy_tcp(tcp4_addr, tproxy_mark)?)
        }?;
        info!("Control plane listening for TPROXY TCPv4 on {}", tcp4_addr);

        let tcp6_listener = match bind_tproxy_tcp(tcp6_addr, tproxy_mark).and_then(|listener| {
            unsafe { tokio::io::unix::AsyncFd::register(listener) }.map_err(anyhow::Error::from)
        }) {
            Ok(l) => {
                info!("Control plane listening for TPROXY TCPv6 on {}", tcp6_addr);
                Some(l)
            }
            Err(e) => {
                // Only a host without an IPv6 stack may leave this slot empty.
                let no_ipv6 = e
                    .downcast_ref::<io::Error>()
                    .and_then(|error| error.raw_os_error())
                    == Some(libc::EAFNOSUPPORT);
                if no_ipv6 {
                    warn!("TPROXY TCPv6 listener unavailable: {}", e);
                    None
                } else {
                    return Err(e.context("bind TPROXY TCPv6 listener"));
                }
            }
        };

        // Parallel UDP listeners: the eBPF datapath hashes each flow's tuple
        // into one of UDP_LISTENER_COUNT sockets per family (sk_lookup.rs);
        // each socket gets its own receive loop task below, so flows drain
        // in parallel across runtime workers.
        const UDP_LISTENER_COUNT: usize = 4;
        let udp4_sockets: Vec<Arc<UdpSocket>> =
            bind_tproxy_udp_listeners(udp4_addr, UDP_LISTENER_COUNT)?
                .into_iter()
                .map(Arc::new)
                .collect();
        info!(
            "Control plane listening for TPROXY UDPv4 x{} on {}",
            udp4_sockets.len(),
            udp4_addr
        );

        let udp6_sockets: Vec<Arc<UdpSocket>> =
            match bind_tproxy_udp_listeners(udp6_addr, UDP_LISTENER_COUNT) {
                Ok(sockets) => {
                    let sockets: Vec<Arc<UdpSocket>> = sockets.into_iter().map(Arc::new).collect();
                    info!(
                        "Control plane listening for TPROXY UDPv6 x{} on {}",
                        sockets.len(),
                        udp6_addr
                    );
                    sockets
                }
                Err(e) => {
                    // Only a host without an IPv6 stack may run with empty
                    // sk_lookup slots; any other failure would black-hole
                    // proxied IPv6 UDP until restart (slots are published
                    // once), so fail startup and let the supervisor retry.
                    let no_ipv6 = e
                        .downcast_ref::<io::Error>()
                        .and_then(|error| error.raw_os_error())
                        == Some(libc::EAFNOSUPPORT);
                    if no_ipv6 {
                        warn!("TPROXY UDPv6 listener unavailable: {}", e);
                        Vec::new()
                    } else {
                        return Err(e.context("bind TPROXY UDPv6 listener group"));
                    }
                }
            };

        Ok(BoundListeners {
            tcp4: tcp4_listener,
            tcp6: tcp6_listener,
            udp4: udp4_sockets,
            udp6: udp6_sockets,
            dns: bound_dns_listener,
            nfqueue_enabled: udp_nfqueue_enabled,
        })
    }

    pub(super) async fn prepare_epoch(
        &mut self,
        listeners: BoundListeners,
    ) -> anyhow::Result<RuntimeEpoch> {
        use std::os::fd::AsRawFd;
        let tcp4 = listeners.tcp4.as_raw_fd();
        let tcp6 = listeners.tcp6.as_ref().map(AsRawFd::as_raw_fd);
        let udp4: Vec<_> = listeners
            .udp4
            .iter()
            .map(|socket| socket.as_raw_fd())
            .collect();
        let udp6: Vec<_> = listeners
            .udp6
            .iter()
            .map(|socket| socket.as_raw_fd())
            .collect();
        let tc = Arc::clone(TcKernelController::require(&self.tc_kernel)?);
        tc.publish_listeners(tcp4, tcp6, &udp4, &udp6).await?;
        let (critical_tx, critical_errors) = mpsc::unbounded_channel();
        let (removal_tx, removal_errors) = mpsc::unbounded_channel();
        let (stop, _) = watch::channel(false);
        let mut epoch = RuntimeEpoch {
            dns: None,
            listeners,
            stop,
            ingress: JoinSet::new(),
            tcp: JoinSet::new(),
            maintenance: OwnedTasks::default(),
            janitor: None,
            removals: None,
            removal_errors,
            critical_errors,
            health_updates: None,
            #[cfg(feature = "legacy-tc")]
            queue: None,
        };
        let prepared = async {
            if let Some(bound) = epoch.listeners.dns.take() {
                epoch.dns = Some(bound.spawn(
                    self.dns_controller.clone(),
                    self.concurrency_limit.clone(),
                    self.stats.clone(),
                    self.drain_tracker.clone(),
                    self.native.clone(),
                    self.diagnostics.clone(),
                    honk_datapath::ScopeId::HOST,
                )?);
            }
            #[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
            let record_flows = self.native.is_some()
                && self
                    .config
                    .read()
                    .await
                    .experimental
                    .native_api
                    .record_flows;
            #[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
            let mut trace_error = None;
            #[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
            let mut trace_unavailable = [false; 2];
            let state = UdpLoopState::new(self, daens_netns_exists());
            for (socket, family) in epoch
                .listeners
                .udp4
                .iter()
                .map(|socket| (socket, "v4"))
                .chain(epoch.listeners.udp6.iter().map(|socket| (socket, "v6")))
            {
                let state = state.clone();
                let socket = Arc::clone(socket);
                let batch = sockets::UdpRecvBatch::new()?;
                #[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
                let mut batch = batch;
                #[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
                if record_flows
                    && let Err(error) = enable_receive_trace(&tc, &mut batch, &socket).await
                {
                    trace_error.get_or_insert(error);
                    trace_unavailable[usize::from(family == "v6")] = true;
                }
                let mut stopping = epoch.stop.subscribe();
                let mut exit = CriticalTaskExit {
                    name: "udp_listener_loop",
                    fatal_tx: critical_tx.clone(),
                    expected: false,
                };
                epoch.ingress.spawn(async move {
                    tokio::select! {
                        biased;
                        _ = stopping.changed() => exit.expected_stop(),
                        _ = udp_listener_loop(state, socket, family, batch) => {},
                    }
                });
            }
            #[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
            let trace_degraded = record_udp_trace(&self.degradations, trace_unavailable);
            #[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
            if trace_degraded && let Some(error) = &trace_error {
                warn!(
                    %error,
                    ipv4_unavailable = trace_unavailable[0],
                    ipv6_unavailable = trace_unavailable[1],
                    "UDP receive trace unavailable"
                );
            }
            epoch.removals = Some(spawn_retirement_worker(
                self.udp_pool.clone(),
                Arc::clone(&tc),
                self.connection_tracker.clone(),
                removal_tx,
                self.tcp_flow_pins.clone(),
                Arc::clone(&self.retirement),
            ));
            epoch.janitor = Some(
                BpfJanitor::new(tc, self.tcp_flow_pins.clone())
                    .with_udp_pool(self.udp_pool.clone())
                    .spawn_supervised(
                        CriticalTaskExit {
                            name: "bpf_janitor",
                            fatal_tx: critical_tx,
                            expected: false,
                        },
                        epoch.stop.subscribe(),
                    ),
            );
            epoch.health_updates = Some(HealthUpdates::start(self));
            // Persisted Selector choices can change after ControlPlane construction.
            // Publish their slots before the candidate epoch opens admission.
            {
                let _config = self.config.read().await;
                let mut ebpf = self.ebpf.write().await;
                let manager = self.group_manager.read();
                let snapshot =
                    initial_route_connectivity(&self.active_routing_plan.read().plan, &manager);
                publish_group_connectivity(ebpf.as_mut(), &snapshot)?;
            }
            #[cfg(feature = "legacy-tc")]
            {
                let sequence_ready = if epoch.listeners.nfqueue_enabled {
                    self.rotate_udp_decision_generation().await?
                } else {
                    false
                };
                match self
                    .start_nfqueue_runtime(epoch.listeners.nfqueue_enabled, sequence_ready)
                    .await
                {
                    Ok(queue) => epoch.queue = queue,
                    Err(error) => {
                        self.degrade_nfqueue_startup(&mut epoch.listeners.nfqueue_enabled, error)
                            .await
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = prepared {
            // Preparation has not opened admission. Cleanup must not borrow the
            // terminal process shutdown path or discard retained API owners.
            let mut cleanup = None;
            retain_error(&mut cleanup, self.quiesce_udp_epoch(Some(&mut epoch)).await);
            retain_error(
                &mut cleanup,
                self.stop_network_epoch(Some(&mut epoch)).await,
            );
            if let Some(cleanup) = cleanup {
                return Err(cleanup
                    .context("runtime candidate cleanup failed")
                    .context(error));
            }
            return Err(error);
        }
        Ok(epoch)
    }

    pub(super) async fn open_epoch(&mut self, epoch: &mut RuntimeEpoch) -> anyhow::Result<()> {
        #[cfg(feature = "legacy-tc")]
        if let Some(queue) = epoch.queue.as_mut()
            && let Err(error) = queue.check_startup_health().await
        {
            self.cleanup_nfqueue_startup_failure(&mut epoch.queue).await;
            epoch.queue = None;
            self.degrade_nfqueue_startup(&mut epoch.listeners.nfqueue_enabled, error.into())
                .await;
        }
        #[cfg(feature = "legacy-tc")]
        let queue_ready = epoch
            .queue
            .as_ref()
            .is_some_and(|queue| queue.sequence_ready);
        #[cfg(not(feature = "legacy-tc"))]
        let queue_ready = false;
        self.initialize_datapath_flags(epoch.listeners.nfqueue_enabled, queue_ready)
            .await?;
        #[cfg(feature = "legacy-tc")]
        if let Some(queue) = epoch.queue.as_ref()
            && queue.sequence_ready
        {
            queue.pending.open_admission();
        }
        self.ebpf.write().await.set_datapath_ready(true)?;
        self.drain_tracker.stop_rejecting();
        Ok(())
    }

    #[cfg(feature = "legacy-tc")]
    pub(in crate::control) async fn warn_lan_self_protection(&self) {
        if !daens_netns_exists() {
            return;
        }
        // The caller holds reload_lock; never retain Config's guard while awaiting Router.
        let config = self.config.read().await.clone();
        let planned_config = Arc::clone(&config);
        let interfaces = match tokio::task::spawn_blocking(move || {
            crate::ebpf::interface::read_and_plan(
                &planned_config.global.lan_interface,
                &planned_config.global.wan_interface,
            )
            .map(|(_, plan)| plan.lan_roots)
        })
        .await
        {
            Ok(Ok(interfaces)) => interfaces,
            result => {
                debug!(
                    ?result,
                    "skip LAN self-protection warning: interface plan unavailable"
                );
                return;
            }
        };
        if interfaces.is_empty() {
            return;
        }
        let addresses = config.local_direct_cidrs();
        let router = self.router.read().await;
        let unconfirmed: Vec<_> = addresses
            .into_iter()
            .filter(|cidr| {
                crate::routing::parse_ip_net_str(cidr)
                    .is_some_and(|network| !router.confirms_lan_self_protection(network.addr()))
            })
            .collect();
        if !unconfirmed.is_empty() {
            warn!(
                lan_interfaces = ?interfaces,
                local_addresses = ?unconfirmed,
                "LAN self-protection coverage could not be confirmed; review explicit direct(must) rules for management access, excluding port 53 if transparent DNS is intended; configured routing is unchanged"
            );
        }
    }
}

/// Whether `socket` records kernel UDP receive traces: `SO_RCVPRIORITY` where
/// the kernel has it, otherwise the eBPF receive trace.
#[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
pub(super) async fn enable_receive_trace(
    tc: &TcKernelController,
    batch: &mut sockets::UdpRecvBatch,
    socket: &tokio::net::UdpSocket,
) -> std::io::Result<()> {
    if batch.enable_trace(socket, None).is_ok() {
        return Ok(());
    }
    let prepare = tc
        .prepare_receive_trace()
        .await
        .map_err(std::io::Error::other)?;
    let trace = match prepare {
        Some(prepare) => tokio::task::spawn_blocking(prepare)
            .await
            .map_err(std::io::Error::other)?,
        None => None,
    };
    batch.enable_trace(socket, trace)
}

/// Kernel UDP receive tracing is only needed while flows are recorded.
#[cfg(all(feature = "native-api", feature = "legacy-tc", target_os = "linux"))]
pub(super) fn record_udp_trace(
    degradations: &crate::degradations::Degradations,
    unavailable: [bool; 2],
) -> bool {
    let component = crate::degradations::Component::UdpTrace;
    let reason = match unavailable {
        [true, false] => "ipv4_unavailable",
        [false, true] => "ipv6_unavailable",
        [true, true] => "unavailable",
        [false, false] => {
            degradations.clear(component);
            return false;
        }
    };
    let issue = crate::degradations::Issue {
        code: "udp_trace_unavailable",
        message: "Kernel UDP receive tracing is unavailable for at least one listener family; recorded UDP flows may lack kernel route evidence.",
        reason,
    };
    let entered = degradations.get(component) != Some(issue);
    degradations.set(component, issue);
    entered
}
