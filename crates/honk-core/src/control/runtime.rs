use super::*;
#[cfg(not(feature = "ebpf"))]
#[allow(dead_code)]
enum NfqueueRuntimeEvent {
    Fatal(anyhow::Error),
    TokenExhausted,
}

#[cfg(not(feature = "ebpf"))]
async fn wait_nfqueue_event(
    _runtime: &mut (),
    _ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
) -> NfqueueRuntimeEvent {
    std::future::pending::<NfqueueRuntimeEvent>().await
}
fn accepts_transparent_connection(drain: &DrainTracker) -> bool {
    !drain.should_reject()
}

/// Fires the control-plane fatal channel when a critical background task
/// exits for any reason (return, panic, or abort). A dead listener loop or
/// janitor otherwise leaves the process alive but unable to serve flows;
/// exiting lets the service manager restart it. Shutdown aborts land after
/// the run loop has left its select, so they never deliver.
pub(super) struct CriticalTaskExit {
    name: &'static str,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
}

impl Drop for CriticalTaskExit {
    fn drop(&mut self) {
        let _ = self.fatal_tx.send(anyhow::anyhow!(
            "critical background task '{}' exited",
            self.name
        ));
    }
}

async fn accept_tcp_with_admission(
    tcp4_listener: &tokio::io::unix::AsyncFd<std::net::TcpListener>,
    tcp6_listener: Option<&tokio::io::unix::AsyncFd<std::net::TcpListener>>,
    concurrency_limit: Arc<tokio::sync::Semaphore>,
    stats: Arc<StatsManager>,
) -> io::Result<(
    TcpStream,
    SocketAddr,
    &'static str,
    tokio::sync::OwnedSemaphorePermit,
)> {
    loop {
        let (mut ready, family) = tokio::select! {
            result = tcp4_listener.readable() => {
                (result?, "v4")
            }
            result = async {
                match tcp6_listener {
                    Some(listener) => listener.readable().await,
                    None => std::future::pending().await,
                }
            } => {
                (result?, "v6")
            }
        };
        let permit = match concurrency_limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                stats.record_tcp_capacity_rejection();
                concurrency_limit
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| io::Error::other("TCP flow admission closed"))?
            }
        };
        match ready.try_io(|listener| listener.get_ref().accept()) {
            Ok(Ok((stream, addr))) => {
                stream.set_nonblocking(true)?;
                return Ok((TcpStream::from_std(stream)?, addr, family, permit));
            }
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => continue,
        }
    }
}

const TCP_ADMISSION_SCALE_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(target_os = "linux")]
fn open_fd_count() -> Option<usize> {
    // ponytail: one procfs scan per second avoids a platform-specific fd broker.
    let count = std::fs::read_dir("/proc/self/fd").ok()?.count();
    Some(count.saturating_sub(1))
}

#[cfg(not(target_os = "linux"))]
fn open_fd_count() -> Option<usize> {
    None
}

fn resize_tcp_admission(
    semaphore: &Arc<tokio::sync::Semaphore>,
    target: &mut usize,
    budget: ResourceBudget,
    stats: &StatsManager,
    open_fds: usize,
) {
    let active_permits = target.saturating_sub(semaphore.available_permits());
    let desired = budget.elastic_tcp_flows(active_permits, open_fds);
    if desired == *target {
        return;
    }

    let previous = *target;
    if desired > previous {
        semaphore.add_permits(desired - previous);
        *target = desired;
    } else {
        let removed = semaphore.forget_permits(previous - desired);
        if removed == 0 {
            return;
        }
        *target = previous - removed;
    }
    stats.set_tcp_flow_limit(*target);
    debug!(
        previous,
        limit = *target,
        active_permits,
        open_fds,
        "resized TCP flow admission budget"
    );
}

async fn run_tcp_admission_scaler(
    semaphore: Arc<tokio::sync::Semaphore>,
    budget: ResourceBudget,
    stats: Arc<StatsManager>,
) {
    let mut target = budget.active_tcp_flows;
    let mut interval = tokio::time::interval(TCP_ADMISSION_SCALE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Some(open_fds) = open_fd_count() {
            resize_tcp_admission(&semaphore, &mut target, budget, &stats, open_fds);
        }
    }
}

#[cfg(feature = "ebpf")]
pub(super) fn disable_nfqueue_for_startup(config: &mut Config, enabled: &mut bool) {
    config.global.nfqueue_enable = false;
    *enabled = false;
}

pub(super) struct OutboundHealthPublisher {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    config: Arc<RwLock<Arc<Config>>>,
    group_manager: SharedGroupManager,
    outbound_id_map: Arc<parking_lot::RwLock<std::collections::HashMap<uuid::Uuid, u8>>>,
    alive_set: Arc<AliveDialerSet>,
}

impl OutboundHealthPublisher {
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        config: Arc<RwLock<Arc<Config>>>,
        group_manager: SharedGroupManager,
        outbound_id_map: Arc<parking_lot::RwLock<std::collections::HashMap<uuid::Uuid, u8>>>,
        alive_set: Arc<AliveDialerSet>,
    ) -> Self {
        Self {
            ebpf,
            config,
            group_manager,
            outbound_id_map,
            alive_set,
        }
    }

    pub(super) async fn publish(self: Arc<Self>, node_id: uuid::Uuid, domain: u32, ipver: u32) {
        // Reload takes these locks in the same order. Keep the config generation
        // pinned while waiting so a queued edge cannot update a recycled slot.
        let config = self.config.read().await;
        let mut backend = self.ebpf.write().await;
        let Some(outbound_idx) = self.outbound_id_map.read().get(&node_id).copied() else {
            return;
        };
        let Some(group) = outbound_idx
            .checked_sub(honk_ebpf_common::OutboundIndex::UserBase as u8)
            .and_then(|idx| config.groups.get(idx as usize))
        else {
            warn!(outbound_idx, %node_id, "outbound health slot has no current group");
            return;
        };
        let probe_domain = match domain {
            1 => ProbeDomain::DnsUdp,
            2 => ProbeDomain::DataUdp,
            _ => ProbeDomain::Tcp,
        };
        let ip_version = if ipver == 1 {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let group_manager = self.group_manager.read().clone();
        let alive = reload::group_datapath_alive(
            group,
            &group_manager,
            &self.alive_set,
            probe_domain,
            ip_version,
        );
        if let Err(error) = backend.set_outbound_alive(outbound_idx, domain, ipver, alive) {
            warn!(
                %error,
                outbound_idx,
                domain,
                ipver,
                "failed to update outbound health in eBPF"
            );
        }
    }
}

impl ControlPlane {
    #[cfg(feature = "ebpf")]
    pub(super) async fn degrade_nfqueue_startup(
        &mut self,
        enabled: &mut bool,
        error: anyhow::Error,
    ) {
        warn!(
            %error,
            "NFQUEUE startup failed before datapath admission; disabling staging for this process"
        );
        self.pending_udp_verdicts = None;
        let mut config = self.config.write().await;
        disable_nfqueue_for_startup(Arc::make_mut(&mut config), enabled);
    }

    /// (Re)push the active routing plan when a previous publication failed.
    /// Reloads clear the dirty flag too; this retry keeps a failed startup
    /// push from dropping every new LAN flow until someone happens to
    /// reload on a quiet network.
    ///
    /// `push_plan` stages with `active=None`, which prunes old-generation
    /// LPM keys; that is safe here only because dirty means no publication
    /// has ever succeeded, so no live readers exist on the other bank.
    pub(in crate::control) async fn repush_routing_if_dirty(&self) {
        if !self
            .routing_publication_dirty
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        // Lock order matches the reload transaction (ebpf before
        // active_routing_plan); the reverse would deadlock against it.
        let mut ebpf = self.ebpf.write().await;
        let plan = self.active_routing_plan.read().clone();
        match routing_matcher::RoutingMatcherBuilder::push_plan(ebpf.as_mut(), &plan) {
            Ok(_) => {
                routing_matcher::RoutingMatcherBuilder::activate_projection(&plan);
                self.routing_publication_dirty
                    .store(false, std::sync::atomic::Ordering::Release);
                info!("routing publication retry succeeded");
            }
            Err(e) => {
                warn!("Failed to push routing to eBPF (non-fatal): {}", e);
            }
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let config = self.config.read().await;
        let tproxy_port = config.global.tproxy_port;
        let tproxy_mark = config.global.tproxy_mark;
        #[cfg(feature = "ebpf")]
        let mut udp_nfqueue_enabled = config.global.nfqueue_enable;
        #[cfg(not(feature = "ebpf"))]
        let udp_nfqueue_enabled = config.global.nfqueue_enable;
        let dns_bind_endpoint = config
            .dns
            .bind_endpoint()
            .map_err(|error| anyhow::anyhow!("invalid dns.bind: {error}"))?;
        drop(config);
        let bound_dns_listener = dns_bind_endpoint
            .as_ref()
            .map(dns_listener::BoundDnsListener::bind)
            .transpose()
            .map_err(|error| anyhow::anyhow!("bind dns.bind listener: {error}"))?;
        let tcp4_addr = SocketAddr::new("0.0.0.0".parse()?, tproxy_port);
        let tcp6_addr = SocketAddr::new("::".parse()?, tproxy_port);
        let udp4_addr = tcp4_addr;
        let udp6_addr = tcp6_addr;

        let tcp4_listener =
            tokio::io::unix::AsyncFd::new(bind_tproxy_tcp(tcp4_addr, tproxy_mark)?)?;
        info!("Control plane listening for TPROXY TCPv4 on {}", tcp4_addr);

        let tcp6_listener = match bind_tproxy_tcp(tcp6_addr, tproxy_mark).and_then(|listener| {
            tokio::io::unix::AsyncFd::new(listener).map_err(anyhow::Error::from)
        }) {
            Ok(l) => {
                info!("Control plane listening for TPROXY TCPv6 on {}", tcp6_addr);
                Some(l)
            }
            Err(e) => {
                // Same rule as the UDPv6 listeners: only a host without an
                // IPv6 stack may continue with the slot empty (the published
                // v4 fd fallback cannot accept v6 flows).
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
                    // A host without an IPv6 stack never sees v6 flows, so
                    // empty sk_lookup slots are harmless there. Any other
                    // failure would black-hole proxied IPv6 UDP until
                    // restart (slots 6-9 are published once) — fail instead
                    // and let the service manager retry.
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

        // Publish listener socket FDs into the eBPF listen_socket_map so TC
        // programs can bpf_sk_assign() proxy-bound packets directly to userspace.
        {
            use std::os::unix::io::AsRawFd;
            let tcp4_fd = tcp4_listener.as_raw_fd();
            let tcp6_fd = tcp6_listener.as_ref().map_or(tcp4_fd, |l| l.as_raw_fd());
            let udp4_fds: Vec<_> = udp4_sockets.iter().map(|s| s.as_raw_fd()).collect();
            let udp6_fds: Vec<_> = udp6_sockets.iter().map(|s| s.as_raw_fd()).collect();
            let mut ebpf = self.ebpf.write().await;
            // A partially published listener set means flows are assigned to
            // sockets that don't exist — run nothing rather than that.
            ebpf.publish_listener_sockets(tcp4_fd, tcp6_fd, &udp4_fds, &udp6_fds)
                .map_err(|e| anyhow::anyhow!("publish listener sockets to eBPF: {}", e))?;
        }

        let mut dns_listener = match bound_dns_listener {
            Some(bound) => {
                let listener = bound
                    .spawn(
                        Arc::clone(&self.dns_controller),
                        Arc::clone(&self.dns_concurrency_limit),
                        Arc::clone(&self.concurrency_limit),
                        Arc::clone(&self.stats),
                        Arc::clone(&self.drain_tracker),
                    )
                    .map_err(|error| anyhow::anyhow!("start dns.bind listener: {error}"))?;
                info!(
                    address = %listener.local_addr(),
                    tcp = dns_bind_endpoint.as_ref().is_some_and(|endpoint| endpoint.tcp_enabled()),
                    udp = dns_bind_endpoint.as_ref().is_some_and(|endpoint| endpoint.udp_enabled()),
                    "Standalone DNS listener started"
                );
                Some(listener)
            }
            None => None,
        };

        // One receive loop per listener socket. The datapath hashes flows
        // into the group (see the comment above), so loops are flow-disjoint.
        let (critical_fatal_tx, mut critical_fatal_rx) = mpsc::unbounded_channel();
        {
            let state = UdpLoopState {
                udp_pool: Arc::clone(&self.udp_pool),
                stats: Arc::clone(&self.stats),
                udp_concurrency_limit: Arc::clone(&self.udp_concurrency_limit),
                dns_concurrency_limit: Arc::clone(&self.dns_concurrency_limit),
                dns_controller: Arc::clone(&self.dns_controller),
                drain: self.drain_tracker.clone(),
                handle: self.spawn_handle(),
            };
            let mut tasks = self.background_tasks.lock().await;
            for (socket, family) in udp4_sockets
                .iter()
                .map(|socket| (socket, "v4"))
                .chain(udp6_sockets.iter().map(|socket| (socket, "v6")))
            {
                let state = state.clone();
                let socket = Arc::clone(socket);
                let fatal_tx = critical_fatal_tx.clone();
                let name = match family {
                    "v4" => "udp_listener_loop/v4",
                    _ => "udp_listener_loop/v6",
                };
                tasks.push(tokio::spawn(async move {
                    let _exit = CriticalTaskExit { name, fatal_tx };
                    udp_listener_loop(state, socket, family).await;
                }));
            }
        }

        let tcp6_listener = tcp6_listener;
        // A persistent token allocator error is ambiguous; only service setup can degrade.
        #[cfg(feature = "ebpf")]
        let nfqueue_sequence_ready = if udp_nfqueue_enabled {
            match self.rotate_udp_decision_generation().await {
                Ok(ready) => ready,
                Err(error) => {
                    if let Some(listener) = dns_listener.as_mut() {
                        listener.stop_accepting();
                        listener.abort_and_join().await;
                    }
                    self.cleanup_pre_admission_failure().await;
                    return Err(anyhow::anyhow!(
                        "prepare UDP decision token allocator: {error:#}"
                    ));
                }
            }
        } else {
            false
        };
        #[cfg(feature = "ebpf")]
        let mut nfqueue_runtime = match self
            .start_nfqueue_runtime(udp_nfqueue_enabled, nfqueue_sequence_ready)
            .await
        {
            Ok(runtime) => runtime,
            Err(error) => {
                self.degrade_nfqueue_startup(&mut udp_nfqueue_enabled, error)
                    .await;
                None
            }
        };
        #[cfg(not(feature = "ebpf"))]
        let mut nfqueue_runtime = ();

        self.repush_routing_if_dirty().await;
        let (mut udp_removal_task, mut udp_removal_fatal_rx) = {
            let (fatal_tx, fatal_rx) = mpsc::unbounded_channel();
            let mut tasks = self.background_tasks.lock().await;

            let janitor = BpfJanitor::new(self.ebpf.clone(), self.tcp_flow_pins.clone());
            tasks.push(janitor.spawn_supervised(CriticalTaskExit {
                name: "bpf_janitor",
                fatal_tx: critical_fatal_tx.clone(),
            }));
            info!("BPF map janitor started");

            let removal_task = spawn_udp_removal_worker(
                Arc::clone(&self.udp_pool),
                self.ebpf.clone(),
                self.connection_tracker.clone(),
                fatal_tx,
            );

            tasks.push(self.udp_pool.spawn_janitor());

            tasks.push(self.sniffer_pool.spawn_janitor());

            tasks.push(crate::control::tcp_sniff::spawn_sniff_neg_cache_janitor(
                self.tcp_sniff_neg_cache.clone(),
            ));
            (removal_task, fatal_rx)
        };

        {
            let alive_set = self.alive_set.clone();
            let interval_secs = {
                let c = self.config.read().await;
                c.global.check_interval_secs
            };
            let check_timeout = std::time::Duration::from_secs(5);

            {
                let c = self.config.read().await;
                honk_outbound::tls::set_tls_mode(&c.global.tls_implementation);
                honk_outbound::tls::set_utls_imitate(&c.global.utls_imitate);
            }

            // Configure HTTP-based health checks from config (Go: TcpCheckOption).
            {
                let c = self.config.read().await;
                let check_url = c.global.tcp_check_url.first().cloned().unwrap_or_default();
                let check_method = if c.global.tcp_check_http_method.is_empty() {
                    "HEAD".to_string()
                } else {
                    c.global.tcp_check_http_method.clone()
                };
                if !check_url.is_empty() {
                    let prober = Arc::new(ProxyHttpProber::new(
                        self.config.clone(),
                        self.proxy_registry.clone(),
                        self.runtime_registry.clone(),
                        check_method.clone(),
                        self.group_manager.clone(),
                    ));
                    alive_set
                        .set_http_probe(prober, check_url, check_method)
                        .await;
                } else {
                    info!(
                        "HTTP health check disabled (no tcp_check_url configured), using TCP connect"
                    );
                }
            }

            // Configure UDP health checks (Go: UdpCheckOption): each probe
            // cycle sends one DNS query through the node's own UDP data
            // path, so nodes with working TCP but broken UDP (e.g. an
            // AnyTLS server without UoT) are marked dead for the UDP
            // domains and excluded from UDP selection.
            {
                let dns_raw = {
                    let c = self.config.read().await;
                    c.global.udp_check_dns.clone()
                };
                let quic_url = {
                    let c = self.config.read().await;
                    if c.groups
                        .iter()
                        .any(|group| group.policy == honk_config::node::GroupPolicy::Score)
                    {
                        c.global.tcp_check_url.first().cloned().unwrap_or_default()
                    } else {
                        String::new()
                    }
                };
                let resolver: crate::outbound::ResolveHook = {
                    let controller = self.dns_controller.clone();
                    Arc::new(move |host: String, port: u16| {
                        let controller = controller.clone();
                        Box::pin(async move {
                            controller
                                .resolve_domain(&host)
                                .await
                                .into_iter()
                                .map(|ip| std::net::SocketAddr::new(ip, port))
                                .collect()
                        })
                    })
                };
                let dns_target = resolve_udp_check_target(&dns_raw, Some(resolver.clone())).await;
                let quic_score_target = if quic_url.is_empty() {
                    None
                } else {
                    resolve_quic_score_target(&quic_url, Some(resolver)).await
                };
                alive_set.set_udp_probe(Arc::new(ProxyUdpProber::new(
                    self.config.clone(),
                    self.proxy_registry.clone(),
                    self.runtime_registry.clone(),
                    self.stats.clone(),
                    dns_target,
                    udp_probe_identity(&dns_raw, dns_target),
                    quic_score_target,
                    self.group_manager.clone(),
                )));
                info!("UDP health check enabled (dns={})", dns_target);
            }

            info!(
                "Starting health check loop (interval={}s, timeout={}s)",
                interval_secs,
                check_timeout.as_secs()
            );
            let health_publisher = Arc::new(OutboundHealthPublisher::new(
                self.ebpf.clone(),
                self.config.clone(),
                self.group_manager.clone(),
                self.outbound_id_map.clone(),
                alive_set.clone(),
            ));
            alive_set.set_ebpf_callback(Box::new(
                move |node_id, _outbound_idx, domain, ipver, _alive| {
                    let _handle =
                        tokio::spawn(Arc::clone(&health_publisher).publish(node_id, domain, ipver));
                },
            ));
            let period = std::time::Duration::from_secs(interval_secs);
            let handle = alive_set.spawn_health_check_loop(period, check_timeout);
            self.background_tasks.lock().await.push(handle);
            info!(
                "Outbound health check loop started (interval={}s)",
                interval_secs
            );
        }

        {
            let pool_handle = self.connection_pool.spawn_janitor();
            self.background_tasks.lock().await.push(pool_handle);
            info!("Connection pool janitor started");
        }

        self.start_preconnect().await;

        // Warm coordinators start only after group/runtime setup and retain
        // this exact registry Arc for their complete lifetime.
        let warm_generation = self.runtime_registry.read().clone();
        self.start_udp_warm_coordinator(Arc::clone(&warm_generation))
            .await;
        self.start_selector_warm_coordinator(warm_generation).await;

        {
            let runtime_registry = self.runtime_registry.clone();
            let handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(honk_outbound::runtime::TLS_REAP_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let generation = runtime_registry.read().clone();
                    let evicted = generation.reap_tls_connectors(std::time::Instant::now());
                    if evicted > 0 {
                        debug!(evicted, "released idle outbound TLS connectors");
                    }
                }
            });
            self.background_tasks.lock().await.push(handle);
        }

        #[cfg(feature = "ebpf")]
        {
            let nfqueue_startup_health_error = match nfqueue_runtime.as_mut() {
                Some(runtime) => runtime.check_startup_health().await.err(),
                None => None,
            };
            if let Some(error) = nfqueue_startup_health_error {
                self.cleanup_nfqueue_startup_failure(&mut nfqueue_runtime)
                    .await;
                nfqueue_runtime = None;
                self.degrade_nfqueue_startup(&mut udp_nfqueue_enabled, error.into())
                    .await;
            }
        }
        #[cfg(feature = "ebpf")]
        let nfqueue_ready = nfqueue_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.sequence_ready);
        #[cfg(not(feature = "ebpf"))]
        let nfqueue_ready = false;
        if let Err(error) = self
            .initialize_datapath_flags(udp_nfqueue_enabled, nfqueue_ready)
            .await
        {
            #[cfg(feature = "ebpf")]
            self.cleanup_nfqueue_startup_failure(&mut nfqueue_runtime)
                .await;
            self.cleanup_started_control_tasks(&mut udp_removal_task, dns_listener.as_mut())
                .await;
            return Err(anyhow::anyhow!("initialize datapath flags: {error:#}"));
        }
        #[cfg(feature = "ebpf")]
        if let Some(runtime) = nfqueue_runtime.as_ref()
            && runtime.sequence_ready
        {
            runtime.pending.open_admission();
        }
        let datapath_open = {
            let mut backend = self.ebpf.write().await;
            backend.set_datapath_ready(true)
        };
        if let Err(error) = datapath_open {
            if let Some(flags) = self.datapath_flags.as_ref() {
                let _ = flags.fence_nfqueue().await;
            }
            #[cfg(feature = "ebpf")]
            self.cleanup_nfqueue_startup_failure(&mut nfqueue_runtime)
                .await;
            self.cleanup_started_control_tasks(&mut udp_removal_task, dns_listener.as_mut())
                .await;
            return Err(anyhow::anyhow!("open eBPF datapath admission: {error}"));
        }
        info!("eBPF datapath admission opened after listener publication");
        let tcp_scaler = tokio::spawn(run_tcp_admission_scaler(
            Arc::clone(&self.concurrency_limit),
            self.resource_budget,
            Arc::clone(&self.stats),
        ));
        self.background_tasks.lock().await.push(tcp_scaler);
        #[cfg(target_os = "linux")]
        if let Err(error) =
            libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
        {
            warn!(%error, "sd_notify readiness failed");
        }

        let mut rx = self.command_rx.take().expect("command_rx already taken");
        let tcp_concurrency_limit = Arc::clone(&self.concurrency_limit);
        let tcp_stats = Arc::clone(&self.stats);
        let drain = self.drain_tracker.clone();
        let fatal_ebpf = Arc::clone(&self.ebpf);
        let mut fatal_error = None;

        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut loop_count = 0u64;
        loop {
            loop_count += 1;
            tokio::select! {
                error = udp_removal_fatal_rx.recv() => {
                    fatal_error = Some(error.unwrap_or_else(|| {
                        anyhow::anyhow!("UDP removal fatal channel closed unexpectedly")
                    }));
                    break;
                }
                error = critical_fatal_rx.recv() => {
                    fatal_error = Some(error.unwrap_or_else(|| {
                        anyhow::anyhow!("critical task fatal channel closed unexpectedly")
                    }));
                    break;
                }
                event = wait_nfqueue_event(&mut nfqueue_runtime, &fatal_ebpf) => {
                    match event {
                        NfqueueRuntimeEvent::Fatal(error) => {
                            fatal_error = Some(error);
                            break;
                        }
                        NfqueueRuntimeEvent::TokenExhausted => {
                            #[cfg(feature = "ebpf")]
                            if let Some(runtime) = nfqueue_runtime.as_mut()
                                && let Err(error) = self
                                    .recover_nfqueue_token_exhaustion(runtime)
                                    .await
                            {
                                fatal_error = Some(anyhow::anyhow!(
                                    "recover exhausted UDP decision token generation: {error:#}"
                                ));
                                break;
                            }
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    trace!(
                        "control plane heartbeat (iteration {}, active_connections={})",
                        loop_count,
                        drain.active_count()
                    );
                    self.repush_routing_if_dirty().await;
                    continue;
                }
                accept_result = accept_tcp_with_admission(
                    &tcp4_listener,
                    tcp6_listener.as_ref(),
                    Arc::clone(&tcp_concurrency_limit),
                    Arc::clone(&tcp_stats),
                ), if accepts_transparent_connection(&drain) => {
                    match accept_result {
                        Ok((stream, addr, family, permit)) => {
                            debug!("Accepted TPROXY TCP{} connection from {}", family, addr);
                            if let Err(e) = set_so_mark_zero(&stream) {
                                warn!("Failed to clear SO_MARK on accepted socket from {}: {}", addr, e);
                            }
                            if !accepts_transparent_connection(&drain) {
                                debug!("Rejecting new connection from {} (draining)", addr);
                                continue;
                            }
                            let tcp_flow = tcp_stats.track_tcp_flow();
                            let guard = ConnectionGuard::new(Arc::clone(&drain));
                            let handle = self.spawn_handle();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _tcp_flow = tcp_flow;
                                let _guard = guard;
                                if let Err(e) = handle.serve_connection(stream, addr).await {
                                    warn!("Error handling TCP{} from {}: {}", family, addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("TPROXY TCP accept error: {}", e);
                            if e.raw_os_error() == Some(libc::EMFILE) {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }

                cmd = rx.recv() => {
                    match cmd {
                        Some(ControlCommand::ReloadConfig { request_id, config }) => {
                            info!("SIGHUP reload request {request_id} started");
                            if self.apply_sighup_config(*config, &drain).await {
                                info!("SIGHUP reload request {request_id} applied");
                            } else {
                                warn!("SIGHUP reload request {request_id} rejected");
                            }
                        }
                        Some(ControlCommand::MergeSubscription {
                            subscription_id,
                            name,
                            nodes,
                        }) => {
                            info!(
                                "Merging {} node(s) from subscription '{}'",
                                nodes.len(),
                                name
                            );
                            if nodes.is_empty() {
                                warn!(
                                    subscription = %name,
                                    "subscription returned no nodes; keeping active nodes"
                                );
                                continue;
                            }
                            let _ = self
                                .merge_subscription_nodes_with_drain(
                                    subscription_id,
                                    nodes,
                                    &drain,
                                )
                                .await;
                        }
                        Some(ControlCommand::NetworkChanged) => {
                            let _reload = self.reload_lock.lock().await;
                            let current = self.config.read().await.clone();
                            let mut next = current.as_ref().clone();
                            let routing_changed = next.ensure_local_direct_rules();
                            let client_subnet_auto = matches!(
                                current.dns.client_subnet_mode(),
                                Ok(Some(honk_config::dns::DnsClientSubnet::Auto { .. }))
                            );
                            if client_subnet_auto {
                                crate::dns::ecs::resolve_client_subnet(&mut next.dns).await;
                            }
                            let client_subnet_changed =
                                next.dns.resolved_client_subnet != current.dns.resolved_client_subnet;
                            let new_config = (routing_changed || client_subnet_changed).then_some(next);
                            let applied = match new_config {
                                Some(new_config) => {
                                    info!(
                                        routing_changed,
                                        client_subnet_changed,
                                        "refreshing runtime after network change"
                                    );
                                    self.apply_resolved_runtime_config_locked(new_config, &drain)
                                        .await
                                }
                                None => true,
                            };
                            drop(_reload);
                            if !applied {
                                warn!("network-triggered runtime refresh rejected");
                                if self
                                    .network_refresh_retry
                                    .as_ref()
                                    .is_none_or(|retry| retry.is_finished())
                                {
                                    self.network_refresh_retry =
                                        Some(spawn_network_refresh_retry(self.command_sender()));
                                }
                            }
                            self.alive_set.notify_network_change();
                        }
                        Some(ControlCommand::Shutdown) | None => break,
                    }
                }
            }
        }

        if let Some(flags) = self.datapath_flags.as_ref()
            && let Err(error) = flags.fence_nfqueue().await
        {
            fatal_error.get_or_insert_with(|| {
                anyhow::anyhow!("failed to fence NFQUEUE during shutdown: {error:#}")
            });
        }
        let datapath_closed = {
            let mut backend = self.ebpf.write().await;
            backend.set_datapath_ready(false)
        };
        if let Err(error) = datapath_closed {
            fatal_error.get_or_insert_with(|| {
                anyhow::anyhow!("failed to close eBPF datapath admission: {error:#}")
            });
        }
        drain.start_rejecting();
        #[cfg(feature = "ebpf")]
        if let Some(runtime) = nfqueue_runtime.as_mut() {
            runtime.begin_pending_drain().await;
            if let Err(error) = runtime.check_startup_health().await {
                fatal_error.get_or_insert_with(|| anyhow::Error::new(error));
            }
        }

        if let Err(error) = self
            .shutdown_datapath(&drain, &mut udp_removal_task, dns_listener.as_mut())
            .await
        {
            fatal_error.get_or_insert(error);
        }

        #[cfg(feature = "ebpf")]
        if let Some(runtime) = nfqueue_runtime.as_mut() {
            if let Err(error) = runtime.shutdown_service().await {
                fatal_error.get_or_insert(error);
            }
            if let Some(error) = runtime.take_shutdown_fatal() {
                fatal_error.get_or_insert_with(|| anyhow::Error::new(error));
            }
            if let Err(error) = runtime.finish_pending_drain().await {
                fatal_error.get_or_insert(error);
            }
            self.pending_udp_verdicts = None;
        }

        if let Some(flags) = self.datapath_flags.as_ref()
            && let Err(error) = flags.disable().await
        {
            fatal_error.get_or_insert_with(|| {
                anyhow::anyhow!("failed to disable datapath flags: {error:#}")
            });
        }

        if let Err(error) = self.finalize_shutdown().await {
            fatal_error.get_or_insert(error);
        }
        if let Some(error) = fatal_error {
            Err(error)
        } else {
            Ok(())
        }
    }
    pub(super) fn spawn_handle(&self) -> ControlPlaneHandle {
        #[cfg(test)]
        self.connection_tracker.enable();
        ControlPlaneHandle {
            config: self.config.clone(),
            router: self.router.clone(),
            proxy_registry: self.proxy_registry.clone(),
            runtime_registry: self.runtime_registry.clone(),
            dns_resolver: self.dns_resolver.clone(),
            group_manager: self.group_manager.clone(),
            stats: self.stats.clone(),
            ebpf: self.ebpf.clone(),
            udp_pool: self.udp_pool.clone(),
            #[cfg(feature = "ebpf")]
            pending_udp_verdicts: self.pending_udp_verdicts.clone(),
            tcp_sniff_neg_cache: self.tcp_sniff_neg_cache.clone(),
            sniffer_pool: self.sniffer_pool.clone(),
            dns_controller: self.dns_controller.clone(),
            alive_set: self.alive_set.clone(),
            connection_pool: self.connection_pool.clone(),
            connection_tracker: self.connection_tracker.clone(),
            tcp_flow_pins: self.tcp_flow_pins.clone(),
            mode_state: self.mode_state.clone(),
        }
    }
}
/// Work produced by the shared IPv4/IPv6 UDP slow-path dispatcher after a
/// fast-path miss. The accept loop never awaits PacketTransport I/O; DNS
/// resolution (when required) runs inside a slow-permit-bounded task.
pub(super) enum UdpSlowPathWork {
    /// Fresh reservation: caller spawns `serve_udp_connection`.
    Initialize(UdpInitLease),
    /// DNS-shaped traffic: slow permit is already held and the payload has
    /// been copied. Run the production DNS controller first; only if it
    /// declines, continue through the same reserve/initializer path.
    DnsThenMaybeInitialize {
        permit: tokio::sync::OwnedSemaphorePermit,
        data: Bytes,
        validated: ValidatedDnsQuery,
        enqueued_at: u32,
    },
    /// Fully handled in the receive loop (enqueued / rejected / dropped).
    Done,
}

/// Shared production admission helper used by both listener families and by
/// focused tests. Order is always:
/// `slow permit → (optional heap copy for DNS task) → reserve_or_enqueue`.
/// Only strict DNS queries whose authoritative destination is port 53 return
/// [`UdpSlowPathWork::DnsThenMaybeInitialize`]; DNS-shaped non-53 UDP stays
/// on ordinary forwarding.
#[cfg(test)]
pub(super) fn begin_udp_slow_path(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    validated_dns: Option<ValidatedDnsQuery>,
) -> UdpSlowPathWork {
    begin_udp_slow_path_at(
        pool,
        stats,
        concurrency_limit,
        src_addr,
        original_dst,
        data,
        validated_dns,
        udp_endpoint::queue_now(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn begin_udp_slow_path_at(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    validated_dns: Option<ValidatedDnsQuery>,
    enqueued_at: u32,
) -> UdpSlowPathWork {
    let Some(permit) = try_admit_udp_slow_path(stats, concurrency_limit) else {
        return UdpSlowPathWork::Done;
    };
    if original_dst.port() == 53
        && let Some(validated) = validated_dns
    {
        // Permit is acquired before the heap copy required to leave the
        // receive buffer for a permit-bounded DNS task.
        return UdpSlowPathWork::DnsThenMaybeInitialize {
            permit,
            data: Bytes::copy_from_slice(data),
            validated,
            enqueued_at,
        };
    }
    match pool.reserve_or_enqueue_at(src_addr, original_dst, data, permit, enqueued_at, stats) {
        EndpointReservation::Initializing(lease) => UdpSlowPathWork::Initialize(lease),
        EndpointReservation::Enqueued
        | EndpointReservation::CapacityRejected
        | EndpointReservation::QueueFull
        | EndpointReservation::IdentityMismatch
        | EndpointReservation::QueueClosed => UdpSlowPathWork::Done,
    }
}

pub(super) struct UdpDnsSlowPathContext<'a> {
    pub(super) pool: &'a Arc<UdpEndpointPool>,
    pub(super) stats: &'a StatsManager,
    pub(super) dns_controller: &'a crate::control::dns_control::DnsController,
    pub(super) src_addr: SocketAddr,
    pub(super) original_dst: SocketAddr,
}

/// Finish a DNS-forced slow path after the slow permit was acquired: run the
/// production DNS controller first. If it handles the packet, do not
/// reserve/enqueue. If it declines, continue through the same
/// `reserve_or_enqueue` path used by ordinary slow traffic.
pub(super) async fn complete_udp_dns_slow_path(
    context: UdpDnsSlowPathContext<'_>,
    permit: tokio::sync::OwnedSemaphorePermit,
    data: &[u8],
    enqueued_at: u32,
    validated: ValidatedDnsQuery,
) -> Option<UdpInitLease> {
    let UdpDnsSlowPathContext {
        pool,
        stats,
        dns_controller,
        src_addr,
        original_dst,
    } = context;
    match dns_controller
        .handle_udp_dns(data, src_addr, original_dst, Some(validated))
        .await
    {
        Ok(true) => return None,
        Ok(false) => {}
        Err(error) => {
            // Preserve the historical UDP fallback: a controller failure is
            // not a reason to drop the original datagram before ordinary
            // endpoint admission has had a chance to forward it.
            warn!(
                "DNS controller error for UDP {} -> {}; continuing UDP: {}",
                src_addr, original_dst, error
            );
        }
    }
    match pool.reserve_or_enqueue_at(src_addr, original_dst, data, permit, enqueued_at, stats) {
        EndpointReservation::Initializing(mut lease) => {
            // The controller was invoked exactly once for this packet. Carry
            // that fact into initialize_udp_connection so an Ok(false) or
            // Err continuation cannot call it again.
            lease.mark_dns_checked();
            Some(lease)
        }
        EndpointReservation::Enqueued
        | EndpointReservation::CapacityRejected
        | EndpointReservation::QueueFull
        | EndpointReservation::IdentityMismatch
        | EndpointReservation::QueueClosed => None,
    }
}

/// Shared IPv4/IPv6 receive-loop dispatcher after a fast-path miss. Acquires
/// the slow permit before any copy/spawn, prefers the DNS controller for
/// DNS-shaped traffic, and only then reserves or enqueues.
/// Everything a UDP listener loop needs, cloned from the control plane once
/// so each socket's loop runs as an independent task (parallel drain).
#[derive(Clone)]
pub(super) struct UdpLoopState {
    pub(super) udp_pool: Arc<UdpEndpointPool>,
    pub(super) stats: Arc<StatsManager>,
    pub(super) udp_concurrency_limit: Arc<tokio::sync::Semaphore>,
    pub(super) dns_concurrency_limit: Arc<tokio::sync::Semaphore>,
    pub(super) dns_controller: Arc<crate::control::dns_control::DnsController>,
    pub(super) drain: Arc<DrainTracker>,
    pub(super) handle: ControlPlaneHandle,
}

/// Receive loop for one UDP listener socket. The eBPF datapath hashes each
/// flow to a specific socket of the group, so loops are flow-disjoint and
/// run in parallel across runtime workers.
async fn udp_listener_loop(state: UdpLoopState, socket: Arc<UdpSocket>, family: &'static str) {
    let mut batch = match UdpRecvBatch::new() {
        Ok(batch) => batch,
        Err(error) => {
            error!("{} UDP recv setup error: {}", family, error);
            return;
        }
    };
    let local_addr = match socket.local_addr() {
        Ok(local_addr) => local_addr,
        Err(error) => {
            error!("{} UDP recv error: {}", family, error);
            return;
        }
    };
    loop {
        if let Err(error) = recv_batch_from_with_orig_dst(&socket, local_addr, &mut batch).await {
            error!("{} UDP recv error: {}", family, error);
            continue;
        }
        let batch_received_at = udp_endpoint::queue_now();
        for index in 0..batch.len() {
            let (data, src_addr, recv_meta) = match batch.packet(index) {
                Ok(packet) => packet,
                Err(error) => {
                    error!("{} UDP recv packet error: {}", family, error);
                    continue;
                }
            };
            let Some(destination) = udp_original_dst(&recv_meta, data) else {
                debug!(
                    "Dropping {} UDP from {} without original-destination provenance",
                    family, src_addr
                );
                continue;
            };
            let original_dst = destination.address;
            let mut validated_dns = destination.validated_dns;
            if original_dst.port() == 53 && validated_dns.is_none() {
                validated_dns = validate_exact_dns_query(data);
            }
            if !accepts_transparent_connection(&state.drain) {
                state.stats.record_udp_slow_permit_closed();
                continue;
            }
            if udp_fast_path_at(
                &state.udp_pool,
                &state.stats,
                data,
                src_addr,
                original_dst,
                validated_dns,
                batch_received_at,
            )
            .await
            {
                continue;
            }
            dispatch_udp_slow_path_at(
                &state,
                src_addr,
                original_dst,
                data,
                validated_dns,
                batch_received_at,
            );
        }
    }
}

#[cfg(test)]
pub(super) fn dispatch_udp_slow_path(
    state: &UdpLoopState,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    validated_dns: Option<ValidatedDnsQuery>,
) {
    dispatch_udp_slow_path_at(
        state,
        src_addr,
        original_dst,
        data,
        validated_dns,
        udp_endpoint::queue_now(),
    );
}

fn dispatch_udp_slow_path_at(
    state: &UdpLoopState,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    validated_dns: Option<ValidatedDnsQuery>,
    enqueued_at: u32,
) {
    let concurrency_limit = if original_dst.port() == 53 && validated_dns.is_some() {
        &state.dns_concurrency_limit
    } else {
        &state.udp_concurrency_limit
    };
    match begin_udp_slow_path_at(
        &state.udp_pool,
        &state.stats,
        concurrency_limit,
        src_addr,
        original_dst,
        data,
        validated_dns,
        enqueued_at,
    ) {
        UdpSlowPathWork::Done => {}
        UdpSlowPathWork::Initialize(lease) => {
            let handle = state.handle.clone();
            let drain = Arc::clone(&state.drain);
            state.udp_pool.spawn_slow_path(async move {
                let _guard = ConnectionGuard::new(drain);
                if let Err(e) = handle.serve_udp_connection(lease).await {
                    warn!(
                        "Error handling UDP from {} (orig {}): {}",
                        src_addr, original_dst, e
                    );
                }
            });
        }
        UdpSlowPathWork::DnsThenMaybeInitialize {
            permit,
            data,
            validated,
            enqueued_at,
        } => {
            let handle = state.handle.clone();
            let guard = ConnectionGuard::new(Arc::clone(&state.drain));
            let pool = Arc::clone(&state.udp_pool);
            let stats = Arc::clone(&state.stats);
            let dns_controller = Arc::clone(&state.dns_controller);
            state.udp_pool.spawn_slow_path(async move {
                // DNS handling is already accepted work. Register it before
                // spawning so reload/shutdown drain cannot miss work before
                // its first poll; keep the guard alive for the task lifetime.
                let _guard = guard;
                let Some(lease) = complete_udp_dns_slow_path(
                    UdpDnsSlowPathContext {
                        pool: &pool,
                        stats: &stats,
                        dns_controller: dns_controller.as_ref(),
                        src_addr,
                        original_dst,
                    },
                    permit,
                    &data,
                    enqueued_at,
                    validated,
                )
                .await
                else {
                    return;
                };
                if let Err(e) = handle.serve_udp_connection(lease).await {
                    warn!(
                        "Error handling UDP from {} (orig {}): {}",
                        src_addr, original_dst, e
                    );
                }
            });
        }
    }
}

/// Test helper for family-symmetric admission: acquire
/// the slow permit then synchronously reserve/enqueue (non-DNS path).
#[cfg(test)]
pub(super) fn reserve_udp_slow_path(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
) -> Option<UdpInitLease> {
    match begin_udp_slow_path(
        pool,
        stats,
        concurrency_limit,
        src_addr,
        original_dst,
        data,
        None,
    ) {
        UdpSlowPathWork::Initialize(lease) => Some(lease),
        UdpSlowPathWork::DnsThenMaybeInitialize {
            permit,
            data,
            enqueued_at,
            ..
        } => {
            match pool.reserve_or_enqueue_at(
                src_addr,
                original_dst,
                &data,
                permit,
                enqueued_at,
                stats,
            ) {
                EndpointReservation::Initializing(lease) => Some(lease),
                _ => None,
            }
        }
        UdpSlowPathWork::Done => None,
    }
}

/// Admit one datagram onto the current UDP slow path after a fast-path miss.
///
/// This is the sole production owner of `udp.slowPermit` accepted/rejected
/// counters. Queue metrics are recorded by `reserve_or_enqueue` / the driver.
pub(super) fn try_admit_udp_slow_path(
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    match concurrency_limit.clone().try_acquire_owned() {
        Ok(permit) => {
            stats.record_udp_slow_permit_accepted();
            Some(permit)
        }
        Err(_) => {
            stats.record_udp_slow_permit_rejected();
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn tcp_admission_resize_tracks_descriptor_headroom() {
        let budget = ResourceBudget::for_nofile(4_096);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(budget.active_tcp_flows));
        let stats = StatsManager::with_tcp_flow_limit(budget.active_tcp_flows);
        let mut target = budget.active_tcp_flows;

        resize_tcp_admission(
            &semaphore,
            &mut target,
            budget,
            &stats,
            budget.fixed_reserve,
        );
        assert_eq!(target, 320);
        assert_eq!(semaphore.available_permits(), 320);
        assert_eq!(stats.tcp_snapshot().limit, 320);

        resize_tcp_admission(
            &semaphore,
            &mut target,
            budget,
            &stats,
            budget.effective_nofile,
        );
        assert_eq!(target, budget.active_tcp_flows);
        assert_eq!(semaphore.available_permits(), budget.active_tcp_flows);
        assert_eq!(stats.tcp_snapshot().limit, budget.active_tcp_flows as u64);
    }

    #[tokio::test]
    async fn tcp_listener_readiness_does_not_exceed_active_flow_limit() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::io::unix::AsyncFd::new(listener).unwrap();
        let limit = Arc::new(tokio::sync::Semaphore::new(1));
        let held_flow = limit.clone().try_acquire_owned().unwrap();
        let stats = Arc::new(StatsManager::with_tcp_flow_limit(1));
        let task_stats = Arc::clone(&stats);
        let task_limit = Arc::clone(&limit);
        let mut task = tokio::spawn(async move {
            accept_tcp_with_admission(&listener, None, task_limit, task_stats).await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"hello").await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                result = &mut task => {
                    let _accepted = result.unwrap().unwrap();
                    panic!("listener reserve became a second active flow while the configured limit was one");
                }
                _ = async {
                    while stats.tcp_snapshot().capacity_rejections == 0 {
                        tokio::task::yield_now().await;
                    }
                } => {}
            }
        })
        .await
        .unwrap();
        drop(held_flow);

        let (mut accepted, _, _, _permit) = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut payload = [0u8; 5];
        accepted.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        assert_eq!(stats.tcp_snapshot().capacity_rejections, 1);
    }

    #[tokio::test]
    async fn critical_task_exit_fires_on_drop() {
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        {
            let _guard = CriticalTaskExit {
                name: "probe_task",
                fatal_tx,
            };
        }
        let error = fatal_rx.recv().await.expect("guard drop must notify");
        assert!(error.to_string().contains("probe_task"));
    }

    #[tokio::test]
    async fn critical_task_exit_silent_while_alive() {
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        let _guard = CriticalTaskExit {
            name: "probe_task",
            fatal_tx,
        };
        fatal_rx
            .try_recv()
            .expect_err("a live guard must not notify");
    }
}
