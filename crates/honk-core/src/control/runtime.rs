use super::*;

/// A normal return is fatal unless the owner acknowledged its requested stop.
pub(super) struct CriticalTaskExit {
    pub(super) name: &'static str,
    pub(super) fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
    pub(super) expected: bool,
}

impl CriticalTaskExit {
    pub(super) fn expected_stop(&mut self) {
        self.expected = true;
    }
}

impl Drop for CriticalTaskExit {
    fn drop(&mut self) {
        if self.expected && !std::thread::panicking() {
            return;
        }
        let _ = self.fatal_tx.send(anyhow::anyhow!(
            "critical background task '{}' exited",
            self.name
        ));
    }
}

pub(super) async fn accept_tcp_with_admission(
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

pub(super) async fn run_tcp_admission_scaler(
    semaphore: Arc<tokio::sync::Semaphore>,
    budget: ResourceBudget,
    stats: Arc<StatsManager>,
    target_cell: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut target = target_cell.load(std::sync::atomic::Ordering::Acquire);
    let mut interval = tokio::time::interval(TCP_ADMISSION_SCALE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Some(open_fds) = open_fd_count() {
            resize_tcp_admission(&semaphore, &mut target, budget, &stats, open_fds);
            target_cell.store(target, std::sync::atomic::Ordering::Release);
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
    alive_set: Arc<AliveDialerSet>,
    /// Per-group bitmask of datapath slots last computed as not alive, so only
    /// transitions are logged. Reloads republish connectivity without this
    /// map, so it restarts with each config generation.
    dead_slots: parking_lot::Mutex<(
        std::sync::Weak<Config>,
        std::collections::HashMap<String, u8>,
    )>,
}

/// Record one group slot's computed liveness; returns whether it flipped.
/// Unknown slots start alive.
fn group_slot_flipped(
    dead_slots: &mut std::collections::HashMap<String, u8>,
    group: &str,
    slot: u8,
    alive: bool,
) -> bool {
    let bit = 1u8 << slot;
    match dead_slots.get_mut(group) {
        Some(mask) if (*mask & bit == 0) != alive => *mask ^= bit,
        Some(_) => return false,
        None if alive => return false,
        None => {
            dead_slots.insert(group.to_owned(), bit);
        }
    }
    true
}

impl OutboundHealthPublisher {
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        config: Arc<RwLock<Arc<Config>>>,
        group_manager: SharedGroupManager,
        alive_set: Arc<AliveDialerSet>,
    ) -> Self {
        Self {
            ebpf,
            config,
            group_manager,
            alive_set,
            dead_slots: parking_lot::Mutex::default(),
        }
    }

    pub(super) async fn publish(self: Arc<Self>, node_id: uuid::Uuid, domain: u32, ipver: u32) {
        // Reload takes these locks in the same order. Keep the config generation
        // pinned while waiting so a queued edge cannot update a recycled slot.
        let config = self.config.read().await;
        let mut backend = self.ebpf.write().await;
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
        let slot = probe_domain as u8 * 2 + ip_version as u8;
        let mut slots = self.dead_slots.lock();
        let (generation, dead_slots) = &mut *slots;
        // The held Weak keeps the old allocation, so its address cannot be reused.
        if !std::ptr::eq(generation.as_ptr(), Arc::as_ptr(&*config)) {
            *generation = Arc::downgrade(&*config);
            dead_slots.clear();
        }
        for (index, group) in config.groups.iter().enumerate() {
            if !group_manager.group_reaches_node(&group.name, node_id) {
                continue;
            }
            let outbound_idx = honk_ebpf_common::OutboundIndex::UserBase as u8 + index as u8;
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
            if group_slot_flipped(dead_slots, &group.name, slot, alive) {
                if alive {
                    info!(
                        group = %group.name,
                        ?probe_domain,
                        ?ip_version,
                        "outbound group is alive again"
                    );
                } else {
                    warn!(
                        group = %group.name,
                        ?probe_domain,
                        ?ip_version,
                        "outbound group has no alive outbound"
                    );
                }
            }
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

    #[cfg(feature = "ebpf")]
    pub(in crate::control) async fn warn_lan_self_protection(&self) {
        if !daens_netns_exists() {
            return;
        }
        // The caller holds reload_lock; never retain Config's guard while awaiting Router.
        let config = self.config.read().await.clone();
        let mut interfaces = crate::configured_interfaces(&config).lan;
        interfaces.retain(|name| crate::netlink::ifindex_of(name).is_ok());
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

    pub(in crate::control) async fn dispatch_control_command(
        &mut self,
        command: ControlCommand,
        drain: &DrainTracker,
        subscription_authorizations: &mut crate::subscription::SubscriptionAuthorizations,
    ) -> bool {
        match command {
            #[cfg(all(feature = "native-api", feature = "clash-api"))]
            ControlCommand::SetRuntimeMode { request, reply } => {
                let _reload = self.reload_lock.lock().await;
                let config = self.config.read().await;
                let result =
                    if let (Some(native), Some(flags)) = (&self.native, &self.datapath_flags) {
                        crate::mode::apply_mode_request(
                            &config,
                            &native.catalog.snapshot().groups,
                            flags,
                            request,
                        )
                        .await
                    } else {
                        Err(super::client::ControlError::Unavailable)
                    };
                let _ = reply.send(result);
            }
            #[cfg(any(feature = "native-api", feature = "clash-api"))]
            ControlCommand::SetSelector { request, reply } => {
                let result = self.apply_selector_request(request).await;
                let _ = reply.send(result);
            }
            ControlCommand::ReloadConfig {
                request_id,
                config,
                diagnostics,
                #[cfg(feature = "native-api")]
                sources,
                #[cfg(feature = "native-api")]
                expected_group_revision,
                result,
            } => {
                info!("SIGHUP reload request {request_id} started");
                let outcome = match self
                    .apply_sighup_config(
                        *config,
                        diagnostics,
                        drain,
                        subscription_authorizations,
                        #[cfg(feature = "native-api")]
                        sources.as_deref(),
                        #[cfg(feature = "native-api")]
                        expected_group_revision.as_deref(),
                    )
                    .await
                {
                    Ok(applied) => applied,
                    Err(error) => {
                        crate::report_runtime_admission_error(&error);
                        ReloadOutcome::Rejected
                    }
                };
                let authorized = if outcome.accepted() {
                    info!(?outcome, "SIGHUP reload request {request_id} applied");
                    let config = self.config.read().await;
                    subscription_authorizations.committed(&config.subscriptions)
                } else {
                    info!("SIGHUP reload request {request_id} rejected");
                    Vec::new()
                };
                if result
                    .send(ReloadReply {
                        outcome,
                        authorized,
                    })
                    .is_err()
                    && outcome.accepted()
                {
                    error!("SIGHUP reload request {request_id} lost its supervisor handoff");
                    return false;
                }
            }
            ControlCommand::MergeSubscription {
                subscription_id,
                revision,
                nodes,
                diagnostics,
                result,
            } => {
                debug!(
                    nodes = nodes.len(),
                    message = "Publishing accepted subscription body"
                );
                let (outcome, rejection) = match self
                    .merge_authorized_subscription_nodes_with_drain(
                        subscription_id,
                        revision,
                        subscription_authorizations,
                        nodes,
                        diagnostics,
                        drain,
                    )
                    .await
                {
                    Ok(outcome) if outcome.accepted() => {
                        debug!(
                            ?outcome,
                            message = "Subscription runtime publication applied"
                        );
                        (outcome, None)
                    }
                    Ok(outcome) => {
                        debug!(message = "Subscription runtime publication rejected");
                        (outcome, None)
                    }
                    Err(error) => {
                        crate::report_runtime_admission_error(&error);
                        (ReloadOutcome::Rejected, Some(error.diagnostic.code))
                    }
                };
                let config = self.config.read().await;
                let _ = result.send(crate::subscription::SubscriptionMergeReply {
                    outcome,
                    node_count: config
                        .nodes
                        .iter()
                        .filter(|node| node.subscription_id == Some(subscription_id))
                        .count(),
                    authorized: subscription_authorizations.committed(&config.subscriptions),
                    rejection,
                });
            }
            ControlCommand::NetworkChanged => {
                let _reload = self.reload_lock.lock().await;
                let current = self.config.read().await.clone();
                let client_subnet_auto = matches!(
                    current.dns.client_subnet_mode(),
                    Ok(Some(honk_config::dns::DnsClientSubnet::Auto { .. }))
                );
                let new_config = if client_subnet_auto {
                    let mut next = current.as_ref().clone();
                    crate::dns::ecs::resolve_client_subnet(&mut next.dns).await;
                    (next.dns.resolved_client_subnet != current.dns.resolved_client_subnet)
                        .then_some(next)
                } else {
                    None
                };
                let applied = match new_config {
                    Some(new_config) => {
                        info!("refreshing DNS ECS after network change");
                        match self
                            .apply_resolved_runtime_config_locked(
                                new_config,
                                drain,
                                crate::config_diagnostics::DiagnosticUpdate::Preserve,
                                None,
                                #[cfg(feature = "native-api")]
                                None,
                            )
                            .await
                        {
                            Ok(outcome) => outcome.accepted(),
                            Err(error) => {
                                crate::report_runtime_admission_error(&error);
                                false
                            }
                        }
                    }
                    None => true,
                };
                #[cfg(feature = "ebpf")]
                if applied {
                    self.warn_lan_self_protection().await;
                }
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
            ControlCommand::Shutdown => return false,
        }
        true
    }

    pub(super) fn spawn_handle(&self) -> ControlPlaneHandle {
        #[cfg(test)]
        self.connection_tracker.enable();
        ControlPlaneHandle {
            config: self.config.clone(),
            diagnostics: self.diagnostics.clone(),
            native: self.native.clone(),
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
                expected: false,
            };
        }
        assert!(fatal_rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn critical_task_exit_silent_while_alive() {
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        let _guard = CriticalTaskExit {
            name: "probe_task",
            fatal_tx,
            expected: false,
        };
        fatal_rx
            .try_recv()
            .expect_err("a live guard must not notify");
    }

    #[test]
    fn expected_stop_preserves_previously_reported_failure() {
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();
        drop(CriticalTaskExit {
            name: "failed",
            fatal_tx: fatal_tx.clone(),
            expected: false,
        });
        let mut stopped = CriticalTaskExit {
            name: "stopped",
            fatal_tx,
            expected: false,
        };
        stopped.expected_stop();
        drop(stopped);
        assert!(fatal_rx.try_recv().is_ok());
        assert!(fatal_rx.try_recv().is_err());
    }

    #[test]
    fn group_slot_logs_only_transitions() {
        let mut dead = std::collections::HashMap::new();
        assert!(!group_slot_flipped(&mut dead, "g", 0, true));
        assert!(group_slot_flipped(&mut dead, "g", 0, false));
        assert!(!group_slot_flipped(&mut dead, "g", 0, false));
        assert!(group_slot_flipped(&mut dead, "g", 5, false));
        assert!(!group_slot_flipped(&mut dead, "other", 0, true));
        assert!(group_slot_flipped(&mut dead, "g", 0, true));
        assert!(!group_slot_flipped(&mut dead, "g", 0, true));
        assert!(!group_slot_flipped(&mut dead, "g", 5, false));
        assert!(group_slot_flipped(&mut dead, "g", 0, false));
    }
}
