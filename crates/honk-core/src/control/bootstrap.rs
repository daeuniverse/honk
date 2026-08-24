use super::*;

impl ControlPlane {
    pub fn new(
        config: Config,
        ebpf: Box<dyn EbpfBackend>,
        router: Router,
        proxy_registry: std::sync::Arc<ProxyRegistry>,
        dns_resolver: DnsResolver,
        dns_forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
    ) -> anyhow::Result<Self> {
        drop(dns_resolver);
        let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(
            &config.dns,
        )?);
        let dns_upstream_pool = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
                &config.dns.upstream,
                dns_router,
                Some(Arc::clone(&proxy_registry)),
                config.nodes.clone(),
                config.groups.clone(),
                honk_outbound::bootstrap::BootstrapResolver::parse(
                    &config.global.bootstrap_resolver,
                ),
                config.dns.strategy.clone(),
            )?
            .with_client_subnet(config.dns.effective_client_subnet()?),
        );
        Self::new_with_upstream_pool(
            config,
            ebpf,
            router,
            proxy_registry,
            dns_forwarder,
            dns_upstream_pool,
        )
    }

    pub fn new_with_upstream_pool(
        config: Config,
        ebpf: Box<dyn EbpfBackend>,
        router: Router,
        proxy_registry: std::sync::Arc<ProxyRegistry>,
        dns_forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
        dns_upstream_pool: Arc<crate::dns::upstream_pool::UpstreamPool>,
    ) -> anyhow::Result<Self> {
        Self::new_with_upstream_pool_and_budget(
            config,
            ebpf,
            router,
            proxy_registry,
            dns_forwarder,
            dns_upstream_pool,
            ResourceBudget::for_nofile(MAX_EFFECTIVE_NOFILE),
        )
    }

    pub(crate) fn new_with_upstream_pool_and_budget(
        config: Config,
        ebpf: Box<dyn EbpfBackend>,
        router: Router,
        proxy_registry: std::sync::Arc<ProxyRegistry>,
        dns_forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
        dns_upstream_pool: Arc<crate::dns::upstream_pool::UpstreamPool>,
        resource_budget: ResourceBudget,
    ) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel(256);
        let effective_log_file = crate::resolved_log_file_path(&config, None);

        // Create alive set for node health checking and pass it into the group
        // manager so dead nodes are excluded from group selection.
        // Mark probe sockets with DAE_BYPASS_MARK so the eBPF datapath does not
        // re-route the control plane's own health check traffic.
        let alive_set = Arc::new(
            crate::outbound::AliveDialerSet::new().with_so_mark(honk_ebpf_common::DAE_BYPASS_MARK),
        );
        // Periodic direct health uses a stable bootstrap target; on-demand
        // URL tests still measure their requested URL.
        let direct_target = direct_check_addr(&config.global.bootstrap_resolver);
        alive_set.set_direct_check_addr(direct_target.clone());
        // Register health checks per the config's group membership; reload
        // re-runs the same sync via `reload_group_manager`.
        let (added, _) = sync_health_check_nodes(&alive_set, &config);
        info!(
            "Registered {}/{} nodes for health check ({} skipped: not in any group)",
            added,
            config.nodes.len(),
            config.nodes.len().saturating_sub(added),
        );
        // Register URLTest groups for idle-aware probe suspension (lazy
        // start: probing pauses after `idle_timeout` without group usage
        // and resumes on the next dial). Members shared with Selector
        // groups are excluded — those are probed unconditionally.
        alive_set.sync_urltest_groups(&urltest_group_registrations(&config));
        alive_set.sync_group_check_urls(&group_check_url_registrations(&config));
        // NodeId → eBPF outbound id for OUTBOUND_CONNECTIVITY_MAP pushes,
        // numbered exactly like push_routing_to_ebpf (group i → UserBase+i).
        // Rebuilt on config reload.
        let outbound_id_map = Arc::new(parking_lot::RwLock::new(build_outbound_id_map(&config)));
        {
            let map = outbound_id_map.clone();
            alive_set.set_outbound_resolver(Some(Arc::new(move |node_id: uuid::Uuid| {
                map.read().get(&node_id).copied()
            })));
        }
        let group_manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive_set.clone()));
        // Custom-URL member resolution: a group's members are probed via
        // their current picks (delay_test_members = tag → representative
        // leaf), so sub-group members are measured through whatever leaf
        // they currently select, and the tag keeps the result. The cell
        // keeps working across reloads (the manager inside is swapped).
        let group_manager = group_manager.into_shared();
        {
            let group_manager = group_manager.clone();
            alive_set.set_score_feedback_factory(move |node_id, context| {
                group_manager.read().feedback_for_node(node_id, context)
            });
        }
        // Per-node runtime registry (single owner of session-layer
        // resources, keyed by Node.id). Invalid node sets (nil/duplicate
        // UUIDs) are a fatal config error at startup.
        let dial_limit = resource_budget.clamp_dials(config.global.max_concurrent_dials);
        let (runtime_registry, _) =
            honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                &config.nodes,
                dial_limit,
                resource_budget.transient_dials,
                None,
            )
            .map_err(|e| anyhow::anyhow!("invalid node set: {}", e))?;
        let runtime_registry = runtime_registry.into_shared();
        info!(
            nofile = resource_budget.effective_nofile,
            fixed = resource_budget.fixed_reserve,
            tcp_flows = resource_budget.active_tcp_flows,
            tcp_max = resource_budget.active_tcp_flows.saturating_mul(2),
            tcp_pool = resource_budget.tcp_pool_entries,
            dials = dial_limit,
            dial_ceiling = resource_budget.transient_dials,
            udp_endpoints = resource_budget.udp_endpoints,
            udp_slow = resource_budget.udp_slow_path,
            dns_slow = resource_budget.dns_slow_path,
            "Control-plane descriptor budget"
        );
        let outbound_runtime = runtime_registry.read().clone();
        dns_upstream_pool.set_runtime_generation(Arc::clone(&outbound_runtime))?;
        {
            let gm_cell = group_manager.clone();
            alive_set.set_url_member_resolver(Some(Arc::new(move |group: &str| {
                gm_cell
                    .read()
                    .delay_test_members(group)
                    .into_iter()
                    .map(|(tag, node)| (tag, node.name))
                    .collect()
            })));
        }

        let pinned_router = Arc::new(Router::new(
            &config.routing.rules,
            &config.routing.default_outbound,
        )?);
        let pinned_groups = group_manager.read().clone();
        dns_upstream_pool.set_group_manager_snapshot(Arc::clone(&pinned_groups));
        dns_upstream_pool.set_traffic_router_snapshot(Arc::clone(&pinned_router));
        let initial_routing_plan = Arc::new(Self::compile_routing_plan(&config, &router)?);
        let initial_push_result = initial_routing_plan.result();
        let ebpf_arc = Arc::new(RwLock::new(ebpf));
        let router_arc = Arc::new(RwLock::new(router));
        let config_arc = Arc::new(RwLock::new(config));
        let initial_runtime =
            crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
                generation: crate::dns::runtime::RuntimeGeneration::new(0),
                forwarder: dns_forwarder.clone(),
                routing_projection: Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
                    0,
                    pinned_router,
                    initial_push_result.domain_bitmaps,
                )),
                outbound_runtime: Some(outbound_runtime),
                transport: dns_upstream_pool,
            });
        let runtime_provider = Arc::new(crate::dns::runtime::DnsServiceProvider::new(
            initial_runtime,
        ));
        let dns_service = crate::dns::DnsService::with_provider(Arc::clone(&runtime_provider));
        let dns_resolver = Arc::new(DnsResolver::with_service(dns_service.clone()));

        let dns_controller = Arc::new(
            crate::control::dns_control::DnsController::new_with_service(
                dns_service,
                ebpf_arc.clone(),
            ),
        );
        // Health-check name resolution shares honk's own DNS forwarder
        // (routing / cache / serve-stale, and always the *current* forwarder
        // across reloads) instead of the raw system resolver; bootstrap DNS
        // stays for node hostnames and startup. The same hook backs the
        // urltest (clash delay) measurements.
        {
            let controller = dns_controller.clone();
            type HookFn = dyn Fn(
                    String,
                    u16,
                ) -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = Vec<std::net::SocketAddr>> + Send>,
                > + Send
                + Sync;
            let make_hook =
                move |controller: std::sync::Arc<crate::control::dns_control::DnsController>| {
                    let hook: Arc<HookFn> = Arc::new(move |host: String, port: u16| {
                        let controller = controller.clone();
                        Box::pin(async move {
                            controller
                                .resolve_domain(&host)
                                .await
                                .into_iter()
                                .map(|ip| std::net::SocketAddr::new(ip, port))
                                .collect()
                        })
                    });
                    hook
                };
            alive_set.set_resolver(make_hook(controller.clone()));
            honk_outbound::urltest::set_urltest_resolver(make_hook(controller));
        }

        let control_plane = Self {
            config: config_arc,
            log_file_override: None,
            effective_log_file,
            ebpf: ebpf_arc,
            router: router_arc,
            proxy_registry,
            dns_resolver,
            dns_controller,
            group_manager,
            runtime_registry,
            stats: Arc::new(StatsManager::with_tcp_flow_limit(
                resource_budget.active_tcp_flows,
            )),
            drain_tracker: Arc::new(DrainTracker::new()),
            udp_pool: Arc::new(UdpEndpointPool::with_capacity_limit(
                resource_budget.udp_endpoints,
            )),
            sniffer_pool: Arc::new(PacketSnifferPool::new()),
            tcp_sniff_neg_cache: Arc::new(crate::control::tcp_sniff::TcpSniffNegCache::new()),
            command_tx: tx,
            command_rx: Some(rx),
            network_refresh_retry: None,
            alive_set,
            connection_pool: Arc::new(ConnectionPool::with_capacity_limit(
                resource_budget.tcp_pool_entries,
            )),
            connection_tracker: Arc::new(ConnectionTracker::new()),
            tcp_flow_pins: Arc::new(TcpFlowPins::default()),
            cache_db: None,
            outbound_id_map,
            resource_budget,
            concurrency_limit: Arc::new(tokio::sync::Semaphore::new(
                super::tcp_admission_capacity(resource_budget.active_tcp_flows),
            )),
            udp_concurrency_limit: Arc::new(tokio::sync::Semaphore::new(
                resource_budget.udp_slow_path,
            )),
            dns_concurrency_limit: Arc::new(tokio::sync::Semaphore::new(
                resource_budget.dns_slow_path,
            )),
            background_tasks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            udp_warm_task: tokio::sync::Mutex::new(None),
            udp_warm_ids: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            selector_warm_task: tokio::sync::Mutex::new(None),
            selector_warm_notify: Arc::new(tokio::sync::Notify::new()),
            selector_warm_ids: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            selector_bare_warm: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
            mode_state: None,
            datapath_flags: None,
            #[cfg(feature = "ebpf")]
            pending_udp_verdicts: None,
            datapath_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            active_routing_plan: Arc::new(parking_lot::RwLock::new(initial_routing_plan)),
            #[cfg(feature = "ebpf")]
            iface_watcher: None,
        };

        // interrupt_connections: when a group's selected node changes, close
        // its tracked connections so they re-dial through the new node.
        install_interrupt_callback(
            &control_plane.group_manager.read(),
            &control_plane.group_manager,
            &control_plane.connection_tracker,
        );
        install_selector_warm_callback(
            &control_plane.group_manager.read(),
            &control_plane.selector_warm_notify,
        );
        // Node death may race an initializer before the listener/background
        // loops start, so this production lifecycle callback belongs to
        // ControlPlane construction rather than `run()` setup.
        control_plane.install_node_death_callback();

        Ok(control_plane)
    }
    pub(crate) fn set_log_file_override(
        &mut self,
        log_file_override: Option<PathBuf>,
        effective_log_file: Option<PathBuf>,
    ) {
        self.log_file_override = log_file_override;
        self.effective_log_file = effective_log_file;
    }

    /// Reap node-bound UDP entries as soon as a real AliveDialerSet transition
    /// reports death. Installing this at construction covers blocked dials and
    /// driver-ready work before `run()` has created listener tasks.
    fn install_node_death_callback(&self) {
        let pool = self.connection_pool.clone();
        let udp_pool = self.udp_pool.clone();
        let config_for_purge = self.config.clone();
        self.alive_set.set_death_callback(Some(Box::new(
            move |node_id: uuid::Uuid, _name: &str| {
                udp_pool.remove_by_node(node_id);
                let node_addr = config_for_purge.try_read().ok().and_then(|c| {
                    c.nodes
                        .iter()
                        .find(|n| n.id == node_id)
                        .map(|n| format!("{}:{}", n.host(), n.port))
                });
                if let Some(addr) = node_addr {
                    pool.purge_node(&addr);
                }
            },
        )));
    }
}
