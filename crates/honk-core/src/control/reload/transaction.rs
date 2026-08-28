use super::*;

#[cfg(test)]
type PreDnsPublicationHook = Box<dyn FnOnce(&Arc<GroupManager>) + Send>;

#[cfg(test)]
static PRE_DNS_PUBLICATION_HOOK: std::sync::LazyLock<
    parking_lot::Mutex<Option<(usize, PreDnsPublicationHook)>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(None));

#[cfg(test)]
pub(in crate::control) struct PreDnsPublicationHookGuard {
    owner: usize,
}

#[cfg(test)]
impl Drop for PreDnsPublicationHookGuard {
    fn drop(&mut self) {
        let mut hook = PRE_DNS_PUBLICATION_HOOK.lock();
        if hook.as_ref().map(|(owner, _)| *owner) == Some(self.owner) {
            hook.take();
        }
    }
}

impl ControlPlane {
    #[cfg(test)]
    pub(in crate::control) fn set_pre_dns_publication_hook(
        &self,
        hook: impl FnOnce(&Arc<GroupManager>) + Send + 'static,
    ) -> PreDnsPublicationHookGuard {
        let owner = self as *const Self as usize;
        *PRE_DNS_PUBLICATION_HOOK.lock() = Some((owner, Box::new(hook)));
        PreDnsPublicationHookGuard { owner }
    }
    /// Atomically publish a rebuilt router, config, group manager, outbound
    /// runtime generation, DNS runtime, and exact eBPF routing plan. Build
    /// failures leave the current generation untouched; an eBPF push failure
    /// replays the exact active plan before admission resumes. SIGHUP and
    /// subscription merges share this command-channel-serialized path.
    pub(in crate::control) async fn apply_runtime_config(
        &self,
        mut new_config: Config,
        drain: &DrainTracker,
    ) -> bool {
        crate::dns::ecs::resolve_client_subnet(&mut new_config.dns).await;
        self.apply_resolved_runtime_config(new_config, drain).await
    }

    /// Publish an explicit runtime configuration through the same transaction
    /// used by SIGHUP and subscription refreshes.
    pub async fn reload_runtime_config(&self, new_config: Config) -> bool {
        self.apply_runtime_config(new_config, &DrainTracker::new())
            .await
    }

    pub(in crate::control) async fn apply_resolved_runtime_config(
        &self,
        new_config: Config,
        drain: &DrainTracker,
    ) -> bool {
        let current_config = self.config.read().await.as_ref().clone();
        let candidate_log_file =
            crate::resolved_log_file_path(&new_config, self.log_file_override.as_deref());
        let restart_required = restart_required_changes(
            &current_config,
            &new_config,
            self.effective_log_file.as_deref(),
            candidate_log_file.as_deref(),
        );
        if !restart_required.is_empty() {
            error!(
                fields = ?restart_required,
                "reload rejected: changed fields require process restart"
            );
            return false;
        }
        let old_plan = self.active_routing_plan.read().clone();

        // Build the candidate completely before mutating live state.
        let new_router = match Router::new(
            &new_config.routing.rules,
            &new_config.routing.default_outbound,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to build new router: {}", e);
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let pinned_router = match Router::new(
            &new_config.routing.rules,
            &new_config.routing.default_outbound,
        ) {
            Ok(router) => Arc::new(router),
            Err(error) => {
                error!(%error, "Failed to build pinned DNS traffic router");
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let old_group_manager = self.group_manager.read().clone();
        let new_group_manager = Arc::new(GroupManager::with_alive_set_and_score_state(
            &new_config.groups,
            &new_config.nodes,
            Some(Arc::clone(&self.alive_set)),
            old_group_manager.score_state(),
        ));
        new_group_manager.migrate_selector_choices_from(&old_group_manager);
        // Build the outbound generation before DNS so every new runtime
        // snapshot captures its own immutable node/session ownership.
        // Nodes whose config survived the reload unchanged reuse the
        // current generation's runtime (live sessions stay up); the
        // transfer is recorded on the old generation only at the commit
        // point below, so an aborted build leaves its ownership untouched.
        let dial_limit = self
            .resource_budget
            .clamp_dials(new_config.global.max_concurrent_dials);
        let (new_runtime_registry, reused_runtime_ids) =
            match honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                &new_config.nodes,
                dial_limit,
                self.resource_budget.transient_dials,
                Some(&self.runtime_registry.read()),
            ) {
                Ok((registry, reused)) => (Arc::new(registry), reused),
                Err(e) => {
                    error!("Failed to build runtime registry (reload aborted): {}", e);
                    self.stop_reload_rejection_if_healthy(drain);
                    return false;
                }
            };
        let (new_dns_forwarder, new_upstream_pool) = match self
            .build_dns_forwarder(
                &new_config,
                Arc::clone(&pinned_router),
                Arc::clone(&new_group_manager),
                Arc::clone(&new_runtime_registry),
            )
            .await
        {
            Ok(runtime) => runtime,
            Err(e) => {
                error!("Failed to build DNS forwarder: {}", e);
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let new_outbound_id_map = build_outbound_id_map(&new_config);
        let old_connectivity =
            group_connectivity_snapshot(&current_config, &old_group_manager, &self.alive_set);
        let new_connectivity =
            group_connectivity_snapshot(&new_config, &new_group_manager, &self.alive_set);
        let bootstrap = new_config.global.bootstrap_resolver.clone();
        let direct_target = super::direct_check_addr(&bootstrap);
        let bootstrap_resolver = honk_outbound::bootstrap::BootstrapResolver::parse(&bootstrap);
        let new_plan = match Self::compile_routing_plan(&new_config, &new_router) {
            Ok(plan) => Arc::new(plan),
            Err(error) => {
                error!(%error, "Failed to compile routing publication");
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let push_result = new_plan.result();
        let generation = crate::dns::runtime::RuntimeGeneration::new(
            self.dns_controller
                .runtime_provider()
                .current_generation()
                .get()
                .saturating_add(1),
        );
        let old_projection_snapshot = {
            let current = self.dns_controller.runtime_provider().acquire();
            Arc::clone(current.runtime().routing_projection())
        };
        let projection_snapshot = Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
            generation.get(),
            Arc::clone(&pinned_router),
            push_result.domain_bitmaps,
        ));
        let old_domain_routes = self
            .dns_controller
            .project_routes(&old_projection_snapshot)
            .into_iter()
            .map(|(ip, bitmap)| (crate::ebpf::maps::ip_addr_to_lpm_key(ip), bitmap))
            .collect::<Vec<_>>();
        let new_domain_routes = self
            .dns_controller
            .project_routes(&projection_snapshot)
            .into_iter()
            .map(|(ip, bitmap)| (crate::ebpf::maps::ip_addr_to_lpm_key(ip), bitmap))
            .collect::<Vec<_>>();
        let new_runtime =
            crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
                generation,
                forwarder: Arc::clone(&new_dns_forwarder),
                routing_projection: Arc::clone(&projection_snapshot),
                outbound_runtime: Some(Arc::clone(&new_runtime_registry)),
                transport: new_upstream_pool,
            });

        let route_count = new_router.route_count();
        let old_static_flags = direct_offload_static_bit(&current_config, &old_plan);
        let new_static_flags = direct_offload_static_bit(&new_config, &new_plan);
        let datapath_flags = if let Some(handle) = self.datapath_flags.clone() {
            handle
        } else {
            if current_config.global.nfqueue_enable || new_config.global.nfqueue_enable {
                error!("datapath flags writer is unavailable during NFQUEUE reload");
                return false;
            }
            let mode_state = self.mode_state.clone().unwrap_or_else(|| {
                Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
                    "Rule", "Proxy",
                )))
            });
            let handle =
                crate::mode::DatapathFlagsHandle::new(Arc::clone(&self.ebpf), mode_state, None);
            if let Err(error) = handle.initialize(old_static_flags, false, false).await {
                error!(%error, "failed to initialize reload-scoped datapath flags writer");
                return false;
            }
            handle
        };
        #[cfg(test)]
        self.ebpf
            .write()
            .await
            .mark_datapath_flags_write_origin(crate::ebpf::DatapathFlagsWriteOrigin::FenceNfqueue);
        if let Err(error) = datapath_flags.fence_nfqueue().await {
            error!(%error, "failed to fence NFQUEUE before reload");
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            self.close_and_drain_pending_udp_admission().await;
            return false;
        }
        drain.start_rejecting();
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.cancel_all().await;
        }
        if !self.udp_pool.cancel_initializers_and_wait().await {
            warn!("UDP initializers did not drain before reload commit");
            self.restore_datapath_flags_after_rejected_reload(
                &datapath_flags,
                old_static_flags,
                drain,
            )
            .await;
            return false;
        }
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.wait_empty().await;
        }
        if !self.udp_pool.wait_for_retirements().await {
            warn!("UDP endpoint retirements did not drain before reload commit");
            self.restore_datapath_flags_after_rejected_reload(
                &datapath_flags,
                old_static_flags,
                drain,
            )
            .await;
            return false;
        }
        let old_registry_result = {
            let mut router_guard = self.router.write().await;
            let mut config_guard = self.config.write().await;
            let mut ebpf = self.ebpf.write().await;
            let mut group_guard = self.group_manager.write();
            let mut outbound_guard = self.outbound_id_map.write();
            let mut plan_guard = self.active_routing_plan.write();
            let mut runtime_guard = self.runtime_registry.write();
            'publication: {
                let provider = self.dns_controller.runtime_provider();
                let publication = provider.prepare_publication(new_runtime);

                let transition_group_count =
                    current_config.groups.len().max(new_config.groups.len());
                if let Err(error) = open_group_connectivity(ebpf.as_mut(), transition_group_count) {
                    let restore = publish_group_connectivity(ebpf.as_mut(), &old_connectivity);
                    error!(%error, ?restore, "Failed to open group connectivity for reload transition");
                    break 'publication Err(());
                }
                let active_generation = match ebpf.active_routing_generation() {
                    Ok(generation) => generation,
                    Err(error) => {
                        error!(%error, "Failed to read active routing generation");
                        break 'publication Err(());
                    }
                };
                let next_generation =
                    active_generation ^ (honk_ebpf_common::ROUTING_GENERATION_COUNT as u32 - 1);
                if let Err(error) =
                    ebpf.stage_domain_routing_generation(next_generation, &new_domain_routes)
                {
                    let restore = publish_group_connectivity(ebpf.as_mut(), &old_connectivity);
                    error!(%error, ?restore, "Failed to stage learned domain routes");
                    break 'publication Err(());
                }
                if let Err(error) = routing_matcher::RoutingMatcherBuilder::push_transition(
                    ebpf.as_mut(),
                    Some(&old_plan),
                    &new_plan,
                ) {
                    let replay = ebpf
                        .stage_domain_routing_generation(next_generation, &old_domain_routes)
                        .and_then(|_| {
                            routing_matcher::RoutingMatcherBuilder::push_transition(
                                ebpf.as_mut(),
                                Some(&old_plan),
                                &old_plan,
                            )
                            .map(|_| ())
                        })
                        .and_then(|_| publish_group_connectivity(ebpf.as_mut(), &old_connectivity));
                    match replay {
                        Ok(()) => {
                            error!(
                                %error,
                                "Failed to push routing to eBPF; exact active plan replayed"
                            );
                        }
                        Err(replay_error) => {
                            error!(
                                %error,
                                %replay_error,
                                "Routing push and active-plan replay failed; datapath unhealthy"
                            );
                            self.datapath_healthy
                                .store(false, std::sync::atomic::Ordering::Release);
                            self.drain_tracker.start_rejecting();
                        }
                    }
                    break 'publication Err(());
                }

                if let Err(error) = publish_group_connectivity(ebpf.as_mut(), &new_connectivity) {
                    warn!(
                        %error,
                        "Failed to publish exact group connectivity after reload; remaining slots stay fail-open"
                    );
                }
                let old_registry =
                    std::mem::replace(&mut *runtime_guard, Arc::clone(&new_runtime_registry));
                new_runtime_registry.activate_background_dial_admission();
                // Commit point for runtime reuse: only now, with the successor
                // published, does the old generation record the transfer and
                // skip those runtimes at drain/shutdown.
                old_registry.mark_moved_out(reused_runtime_ids);
                new_group_manager.publish_score_membership();
                #[cfg(test)]
                if let Some(hook) = {
                    let mut hook = PRE_DNS_PUBLICATION_HOOK.lock();
                    (hook.as_ref().map(|(owner, _)| *owner) == Some(self as *const Self as usize))
                        .then(|| hook.take().expect("matching hook exists").1)
                } {
                    hook(&new_group_manager);
                }
                publication.commit();
                *router_guard = new_router;
                *config_guard = Arc::new(new_config);
                *group_guard = Arc::clone(&new_group_manager);
                *outbound_guard = new_outbound_id_map;
                *plan_guard = Arc::clone(&new_plan);
                // The projection worker takes eBPF before its generation fence;
                // install the snapshot under the same lock so no old batch can
                // enter the newly activated datapath generation.
                self.dns_controller
                    .update_projection_snapshot(projection_snapshot);
                Ok(old_registry)
            }
        };
        let old_registry = match old_registry_result {
            Ok(old_registry) => old_registry,
            Err(()) => {
                self.restore_datapath_flags_after_rejected_reload(
                    &datapath_flags,
                    old_static_flags,
                    drain,
                )
                .await;
                return false;
            }
        };

        routing_matcher::RoutingMatcherBuilder::activate_projection(&new_plan);
        honk_outbound::bootstrap::set_global(bootstrap_resolver);
        self.alive_set.set_direct_check_addr(direct_target);
        install_interrupt_callback(
            &new_group_manager,
            &self.group_manager,
            &self.connection_tracker,
        );
        install_selector_warm_callback(&new_group_manager, &self.selector_warm_notify);
        // No new generation-owned work may start on the old snapshot. Its
        // DNS runtime still owns it until old leases and transports retire;
        // only then do the pools enter graceful session drain.
        old_registry.begin_retirement();
        self.stop_udp_warm_coordinator().await;
        self.stop_selector_warm_coordinator().await;
        self.start_udp_warm_coordinator(Arc::clone(&new_runtime_registry))
            .await;
        self.start_selector_warm_coordinator(new_runtime_registry)
            .await;
        if let Some(ref db) = self.cache_db {
            let db_cb = Arc::clone(db);
            new_group_manager.set_persist_callback(Some(Arc::new(move |group, node| {
                db_cb.save_selector_choice(group, node);
            })));
        }
        {
            let config = self.config.read().await;
            let _ = sync_health_check_nodes(&self.alive_set, &config);
            self.alive_set
                .sync_urltest_groups(&urltest_group_registrations(&config));
            self.alive_set
                .sync_group_check_urls(&group_check_url_registrations(&config));
        }
        #[cfg(test)]
        self.ebpf
            .write()
            .await
            .mark_datapath_flags_write_origin(crate::ebpf::DatapathFlagsWriteOrigin::SetStatic);
        if let Err(error) = datapath_flags.set_static(new_static_flags).await {
            error!(%error, "failed to publish reloaded datapath flags");
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return true;
        }
        self.open_pending_udp_admission();
        #[cfg(test)]
        self.ebpf
            .write()
            .await
            .mark_datapath_flags_write_origin(crate::ebpf::DatapathFlagsWriteOrigin::ReopenNfqueue);
        if let Err(error) = datapath_flags.reopen_nfqueue().await {
            error!(%error, "failed to reopen NFQUEUE after reload");
            self.close_and_drain_pending_udp_admission().await;
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return true;
        }
        info!("Configuration applied — {} routes active", route_count);

        self.stop_reload_rejection_if_healthy(drain);
        true
    }

    async fn restore_datapath_flags_after_rejected_reload(
        &self,
        datapath_flags: &crate::mode::DatapathFlagsHandle,
        old_static_flags: u32,
        drain: &DrainTracker,
    ) {
        #[cfg(test)]
        self.ebpf
            .write()
            .await
            .mark_datapath_flags_write_origin(crate::ebpf::DatapathFlagsWriteOrigin::SetStatic);
        if let Err(error) = datapath_flags.set_static(old_static_flags).await {
            error!(%error, "failed to restore datapath flags after rejected reload");
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return;
        }
        if !self.is_datapath_healthy() {
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return;
        }
        self.open_pending_udp_admission();
        #[cfg(test)]
        self.ebpf
            .write()
            .await
            .mark_datapath_flags_write_origin(crate::ebpf::DatapathFlagsWriteOrigin::ReopenNfqueue);
        if let Err(error) = datapath_flags.reopen_nfqueue().await {
            error!(%error, "failed to reopen NFQUEUE after rejected reload");
            self.close_and_drain_pending_udp_admission().await;
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return;
        }
        drain.stop_rejecting();
    }

    fn open_pending_udp_admission(&self) {
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.open_admission();
        }
    }

    async fn close_and_drain_pending_udp_admission(&self) {
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.cancel_all().await;
        }
        if !self.udp_pool.cancel_initializers_and_wait().await {
            warn!("UDP initializers did not drain after NFQUEUE reopen failure");
        }
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.wait_empty().await;
        }
        if !self.udp_pool.wait_for_retirements().await {
            warn!("UDP endpoint retirements did not drain after NFQUEUE reopen failure");
        }
    }

    /// End reload admission once the datapath is known healthy.
    fn stop_reload_rejection_if_healthy(&self, drain: &DrainTracker) {
        if self.is_datapath_healthy() {
            drain.stop_rejecting();
        } else {
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
        }
    }

    /// Build a DNS forwarder from an explicit config (used by the reload
    /// pipeline's build phase — must not read live state, so the caller can
    /// abort before commit without having mutated anything).
    async fn build_dns_forwarder(
        &self,
        config: &Config,
        router: Arc<Router>,
        group_manager: Arc<GroupManager>,
        runtime_generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) -> anyhow::Result<(
        Arc<crate::dns::forwarder::DnsForwarder>,
        Arc<crate::dns::upstream_pool::UpstreamPool>,
    )> {
        let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(
            &config.dns,
        )?);
        let dns_upstream_pool = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
                &config.dns.upstream,
                dns_router.clone(),
                Some(self.proxy_registry.clone()),
                config.nodes.clone(),
                config.groups.clone(),
                honk_outbound::bootstrap::BootstrapResolver::parse(
                    &config.global.bootstrap_resolver,
                ),
                config.dns.strategy.clone(),
            )?
            .with_client_subnet(config.dns.effective_client_subnet()?)
            .with_runtime_generation(runtime_generation)
            .with_timeouts(
                std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
                std::time::Duration::from_millis(config.global.connect_timeout_ms),
            )
            // Same SharedGroupManager + traffic Router cells as the data path
            // (dae: Route DNS server IP; explicit `-> tag` still forces a group).
            .with_group_manager_snapshot(group_manager)
            .with_traffic_router_snapshot(router),
        );
        let forwarder = Arc::new(
            crate::dns::forwarder::DnsForwarder::new(
                Arc::clone(&dns_upstream_pool) as Arc<dyn crate::dns::forwarder::DnsUpstreamPool>,
                self.dns_controller.cache().await,
                dns_router,
            )
            .with_timeouts(
                std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
                std::time::Duration::from_millis(config.global.connect_timeout_ms),
            )
            .with_strategy(config.dns.strategy.clone())
            .with_cache_enabled(config.dns.cache.enabled)
            .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_policy_from_config(&config.dns)?
            .with_hosts_from_config(&config.dns)?,
        );
        Ok((forwarder, dns_upstream_pool))
    }
}
