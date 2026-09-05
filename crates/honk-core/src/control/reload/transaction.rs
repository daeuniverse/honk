use super::*;

#[cfg(test)]
pub(in crate::control) struct PreDnsPublicationHookGuard<'a> {
    hook: &'a parking_lot::Mutex<Option<PreDnsPublicationHook>>,
}

#[cfg(test)]
impl Drop for PreDnsPublicationHookGuard<'_> {
    fn drop(&mut self) {
        self.hook.lock().take();
    }
}

fn domain_routes_eq(
    left: &[(crate::ebpf::maps::LpmKey, honk_ebpf_common::DomainRouting)],
    right: &[(crate::ebpf::maps::LpmKey, honk_ebpf_common::DomainRouting)],
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|((left_key, left), (right_key, right))| {
                crate::ebpf::maps::lpm_key_bytes(left_key)
                    == crate::ebpf::maps::lpm_key_bytes(right_key)
                    && left.bitmap == right.bitmap
            })
}

fn rebase_subscription_nodes(current: &Config, candidate: &mut Config) {
    let mut static_nodes = Vec::with_capacity(candidate.nodes.len());
    let mut candidate_subscription_nodes =
        std::collections::HashMap::<uuid::Uuid, Vec<Node>>::new();
    for node in std::mem::take(&mut candidate.nodes) {
        if let Some(subscription_id) = node.subscription_id {
            candidate_subscription_nodes
                .entry(subscription_id)
                .or_default()
                .push(node);
        } else {
            static_nodes.push(node);
        }
    }
    let mut matched_previous = std::collections::HashSet::new();

    for subscription in candidate.subscriptions.iter_mut().filter(|sub| sub.enabled) {
        let candidate_id = subscription.id;
        if let Some(previous) = current.subscriptions.iter().find(|previous| {
            crate::subscription::same_subscription_fetch_identity(previous, subscription)
                && !matched_previous.contains(&previous.id)
        }) {
            matched_previous.insert(previous.id);
            subscription.id = previous.id;
            let current_nodes = current
                .nodes
                .iter()
                .filter(|node| node.subscription_id == Some(previous.id));
            if current_nodes.clone().next().is_some() {
                static_nodes.extend(current_nodes.cloned());
                continue;
            }
        }

        if let Some(mut nodes) = candidate_subscription_nodes.remove(&candidate_id) {
            for node in &mut nodes {
                node.subscription_id = Some(subscription.id);
            }
            static_nodes.extend(nodes);
        }
    }

    candidate.nodes = static_nodes;
    honk_config::parser::resolve_group_filters(
        &mut candidate.groups,
        &candidate.nodes,
        &candidate.subscriptions,
    );
}

impl ControlPlane {
    #[cfg(test)]
    pub(in crate::control) fn set_pre_dns_publication_hook(
        &self,
        hook: impl FnOnce(&Arc<GroupManager>) + Send + 'static,
    ) -> PreDnsPublicationHookGuard<'_> {
        *self.pre_dns_publication_hook.lock() = Some(Box::new(hook));
        PreDnsPublicationHookGuard {
            hook: &self.pre_dns_publication_hook,
        }
    }
    /// Atomically publish a rebuilt router, config, group manager, outbound
    /// runtime generation, DNS runtime, and exact eBPF routing plan. Build
    /// failures leave the current generation untouched; an eBPF push failure
    /// replays the exact active plan before admission resumes. SIGHUP,
    /// subscription merges, and public callers share this serialized path.
    pub(in crate::control) async fn apply_runtime_config(
        &self,
        new_config: Config,
        drain: &DrainTracker,
    ) -> bool {
        let _reload = self.reload_lock.lock().await;
        self.apply_runtime_config_locked(new_config, drain).await
    }

    /// Apply a SIGHUP candidate after rebasing its in-memory subscription
    /// nodes against the snapshot being replaced. The signal task may have
    /// prepared the candidate while another runtime update was committing.
    pub(in crate::control) async fn apply_sighup_config(
        &self,
        mut new_config: Config,
        drain: &DrainTracker,
        authorizations: &mut crate::subscription::SubscriptionAuthorizations,
    ) -> bool {
        let _reload = self.reload_lock.lock().await;
        let current = self.config.read().await.clone();
        rebase_subscription_nodes(&current, &mut new_config);
        new_config.ensure_local_direct_rules();
        crate::dns::ecs::resolve_client_subnet(&mut new_config.dns).await;
        self.apply_resolved_runtime_config_locked_with_authorizations(
            new_config,
            drain,
            Some(authorizations),
        )
        .await
    }

    pub(in crate::control) async fn apply_runtime_config_locked(
        &self,
        mut new_config: Config,
        drain: &DrainTracker,
    ) -> bool {
        crate::dns::ecs::resolve_client_subnet(&mut new_config.dns).await;
        self.apply_resolved_runtime_config_locked(new_config, drain)
            .await
    }

    /// Publish an explicit runtime configuration through the same transaction
    /// used by SIGHUP and subscription refreshes.
    pub async fn reload_runtime_config(&self, new_config: Config) -> bool {
        let drain = Arc::clone(&self.drain_tracker);
        self.apply_runtime_config(new_config, &drain).await
    }

    pub(in crate::control) async fn apply_resolved_runtime_config_locked(
        &self,
        new_config: Config,
        drain: &DrainTracker,
    ) -> bool {
        self.apply_resolved_runtime_config_locked_with_authorizations(new_config, drain, None)
            .await
    }

    async fn apply_resolved_runtime_config_locked_with_authorizations(
        &self,
        mut new_config: Config,
        drain: &DrainTracker,
        authorizations: Option<&mut crate::subscription::SubscriptionAuthorizations>,
    ) -> bool {
        if let Err(error) =
            crate::subscription::validate_subscription_ids(&new_config.subscriptions)
        {
            error!(%error, "reload rejected: invalid subscription ids");
            return false;
        }
        let current_router = self.router.read().await.clone();
        let current_config = self.config.read().await.clone();
        if authorizations.is_none()
            && !crate::subscription::same_subscription_worker_set(
                &current_config.subscriptions,
                &new_config.subscriptions,
            )
        {
            error!("reload rejected: subscription worker changes require the control command path");
            return false;
        }
        let config_unchanged = effective_config_unchanged(current_config.as_ref(), &mut new_config);
        let current_dns_forwarder = self.dns_controller.forwarder();
        let current_dns_router = current_dns_forwarder.routing_snapshot();
        if config_unchanged
            && !self
                .routing_publication_dirty
                .load(std::sync::atomic::Ordering::Acquire)
            && self.is_datapath_healthy()
        {
            let traffic_geo = current_router.geo_requirements();
            let dns_geo = current_dns_router.geo_requirements_snapshot();
            let geo_probe = crate::routing::GeoSourceSet::probe_union(traffic_geo, dns_geo);
            let traffic_geo_fingerprint = geo_probe.fingerprint_for(traffic_geo);
            let dns_geo_fingerprint = geo_probe.fingerprint_for(dns_geo);
            let hosts_fingerprint =
                match crate::dns::forwarder::HostsSourceSet::probe_fingerprint(&new_config.dns) {
                    Ok(fingerprint) => fingerprint,
                    Err(error) => {
                        error!(%error, "Failed to fingerprint DNS hosts snapshot");
                        self.stop_reload_rejection_if_healthy(drain);
                        return false;
                    }
                };
            if current_router.geo_fingerprint() == traffic_geo_fingerprint
                && current_dns_router.geo_fingerprint() == dns_geo_fingerprint
                && current_dns_forwarder.policy_id().is_some_and(|policy| {
                    policy.matches_artifacts(&hosts_fingerprint, &dns_geo_fingerprint)
                })
            {
                info!("Configuration unchanged — retaining active runtime generation");
                return true;
            }
        }
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

        #[cfg(feature = "reload-bench-counters")]
        self.reload_slow_path_entries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let traffic_geo = crate::routing::GeoRequirements::for_traffic(&new_config.routing.rules);
        let dns_geo = crate::dns::routing::DnsRouter::geo_requirements(&new_config.dns);
        let geo_requirements = traffic_geo.union(&dns_geo);
        let geo_sources = crate::routing::GeoSourceSet::load(&geo_requirements);
        let traffic_geo_fingerprint = geo_sources.fingerprint_for(&traffic_geo);
        let dns_geo_fingerprint = geo_sources.fingerprint_for(&dns_geo);
        let hosts_sources = match crate::dns::forwarder::HostsSourceSet::load(&new_config.dns) {
            Ok(sources) => sources,
            Err(error) => {
                error!(%error, "Failed to load DNS hosts snapshot");
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let candidate_dns_policy = match crate::dns::policy::PolicyId::from_config_with_artifacts(
            &new_config.dns,
            &hosts_sources.fingerprint(),
            &dns_geo_fingerprint,
        ) {
            Ok(policy) => policy,
            Err(error) => {
                error!(%error, "Failed to derive DNS policy identity");
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let old_plan = self.active_routing_plan.read().clone();
        let reuse_routing_state = routing_state_reusable(&current_config, &new_config)
            && current_router.geo_fingerprint() == traffic_geo_fingerprint;
        // Build the candidate completely before mutating live state.
        let new_router = if reuse_routing_state {
            current_router
        } else {
            match Router::new_with_geo_sources(
                &new_config.routing.rules,
                &new_config.routing.default_outbound,
                &geo_sources,
            ) {
                Ok(router) => router,
                Err(error) => {
                    error!(%error, "Failed to build new router");
                    self.stop_reload_rejection_if_healthy(drain);
                    return false;
                }
            }
        };
        let pinned_router = Arc::new(new_router.clone());
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
        let reuse_dns_router = dns_routing_state_reusable(&current_config, &new_config)
            && current_dns_router.geo_fingerprint() == dns_geo_fingerprint;
        let dns_router = if reuse_dns_router {
            current_dns_router
        } else {
            match crate::dns::routing::DnsRouter::new_with_geo_sources(
                &new_config.dns,
                &geo_sources,
            ) {
                Ok(router) => Arc::new(router),
                Err(error) => {
                    error!(%error, "Failed to build DNS router");
                    self.stop_reload_rejection_if_healthy(drain);
                    return false;
                }
            }
        };
        let current_hosts = current_dns_forwarder.hosts_snapshot();
        let hosts_changed = hosts_sources.fingerprint() != current_hosts.fingerprint();
        let hosts_snapshot = if !hosts_changed {
            current_hosts
        } else {
            match hosts_sources.parse() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    error!(%error, "Failed to parse DNS hosts snapshot");
                    self.stop_reload_rejection_if_healthy(drain);
                    return false;
                }
            }
        };
        let (new_dns_forwarder, new_upstream_pool) = match self
            .build_dns_forwarder(
                &new_config,
                Arc::clone(&pinned_router),
                Arc::clone(&new_group_manager),
                Arc::clone(&new_runtime_registry),
                candidate_dns_policy,
                dns_router,
                hosts_snapshot,
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
        let bootstrap = new_config.global.bootstrap_resolver.clone();
        let direct_target = super::direct_check_addr(&bootstrap);
        let bootstrap_resolver = honk_outbound::bootstrap::BootstrapResolver::parse(&bootstrap);
        let new_plan = if reuse_routing_state {
            Arc::clone(&old_plan)
        } else {
            match Self::compile_routing_plan(&new_config, &new_router) {
                Ok(plan) => Arc::new(plan),
                Err(error) => {
                    error!(%error, "Failed to compile routing publication");
                    self.stop_reload_rejection_if_healthy(drain);
                    return false;
                }
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
            error!(error = %format_args!("{error:#}"), "failed to fence NFQUEUE before reload");
            self.close_and_drain_pending_udp_admission().await;
            // Nothing was torn down yet: restore the old flags and keep
            // serving instead of rejecting new connections forever.
            self.restore_datapath_flags_after_rejected_reload(
                &datapath_flags,
                old_static_flags,
                drain,
            )
            .await;
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
            let projection_publication = self.dns_controller.prepare_projection_publication();
            let mut group_guard = self.group_manager.write();
            let mut outbound_guard = self.outbound_id_map.write();
            let mut plan_guard = self.active_routing_plan.write();
            let mut runtime_guard = self.runtime_registry.write();
            'publication: {
                let old_connectivity = group_connectivity_snapshot(
                    &current_config,
                    &old_group_manager,
                    &self.alive_set,
                );
                let new_connectivity =
                    group_connectivity_snapshot(&new_config, &new_group_manager, &self.alive_set);
                let mut old_domain_routes = projection_publication
                    .project(&old_projection_snapshot)
                    .into_iter()
                    .map(|(ip, bitmap)| (crate::ebpf::maps::ip_addr_to_lpm_key(ip), bitmap))
                    .collect::<Vec<_>>();
                let mut new_domain_routes = projection_publication
                    .project(&projection_snapshot)
                    .into_iter()
                    .map(|(ip, bitmap)| (crate::ebpf::maps::ip_addr_to_lpm_key(ip), bitmap))
                    .collect::<Vec<_>>();
                old_domain_routes
                    .sort_unstable_by_key(|(key, _)| crate::ebpf::maps::lpm_key_bytes(key));
                new_domain_routes
                    .sort_unstable_by_key(|(key, _)| crate::ebpf::maps::lpm_key_bytes(key));
                // An unhealthy latch may have left the routing bank torn;
                // force a full re-push so a completed slow path repairs it.
                let routing_publication_needed = !self.is_datapath_healthy()
                    || self
                        .routing_publication_dirty
                        .load(std::sync::atomic::Ordering::Acquire)
                    || !old_plan.semantically_eq(&new_plan)
                    || !domain_routes_eq(&old_domain_routes, &new_domain_routes);
                let bitmap_generation_fence_needed =
                    routing_publication_needed || !reuse_routing_state;
                let provider = self.dns_controller.runtime_provider();
                let publication = provider.prepare_publication(new_runtime);

                let transition_group_count =
                    current_config.groups.len().max(new_config.groups.len());
                if let Err(error) = open_group_connectivity(ebpf.as_mut(), transition_group_count) {
                    let restore = publish_group_connectivity(ebpf.as_mut(), &old_connectivity);
                    error!(%error, ?restore, "Failed to open group connectivity for reload transition");
                    break 'publication Err(());
                }
                if routing_publication_needed {
                    let active_generation = match ebpf.active_routing_generation() {
                        Ok(generation) => generation,
                        Err(error) => {
                            let restore =
                                publish_group_connectivity(ebpf.as_mut(), &old_connectivity);
                            error!(%error, ?restore, "Failed to read active routing generation");
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
                            .and_then(|_| {
                                publish_group_connectivity(ebpf.as_mut(), &old_connectivity)
                            });
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
                }
                if bitmap_generation_fence_needed {
                    routing_matcher::RoutingMatcherBuilder::activate_projection(&new_plan);
                }
                if routing_publication_needed {
                    self.routing_publication_dirty
                        .store(false, std::sync::atomic::Ordering::Release);
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
                    let mut hook = self.pre_dns_publication_hook.lock();
                    hook.take()
                } {
                    hook(&new_group_manager);
                }
                publication.commit();
                *router_guard = new_router;
                *config_guard = Arc::new(new_config);
                if let Some(authorizations) = authorizations {
                    authorizations
                        .publish(&current_config.subscriptions, &config_guard.subscriptions);
                }
                *group_guard = Arc::clone(&new_group_manager);
                *outbound_guard = new_outbound_id_map;
                if routing_publication_needed {
                    *plan_guard = Arc::clone(&new_plan);
                }
                // The projection worker takes eBPF before its generation fence;
                // publish under both locks so an old batch cannot enter this snapshot.
                projection_publication.commit(projection_snapshot);
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

        // A completed slow path has republished everything a latch could
        // have torn; re-arm.
        self.datapath_healthy
            .store(true, std::sync::atomic::Ordering::Release);
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
            warn!("UDP initializers did not drain during admission teardown");
        }
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.wait_empty().await;
        }
        if !self.udp_pool.wait_for_retirements().await {
            warn!("UDP endpoint retirements did not drain during admission teardown");
        }
    }

    /// End reload admission once the datapath is known healthy.
    fn stop_reload_rejection_if_healthy(&self, drain: &DrainTracker) {
        if self.is_datapath_healthy() {
            drain.stop_rejecting();
            self.drain_tracker.stop_rejecting();
        } else {
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
        }
    }

    /// Build a DNS forwarder from an explicit config (used by the reload
    /// pipeline's build phase — must not read live state, so the caller can
    /// abort before commit without having mutated anything).
    #[allow(clippy::too_many_arguments)]
    async fn build_dns_forwarder(
        &self,
        config: &Config,
        router: Arc<Router>,
        group_manager: Arc<GroupManager>,
        runtime_generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        dns_policy: crate::dns::policy::PolicyId,
        dns_router: Arc<crate::dns::routing::DnsRouter>,
        hosts_snapshot: crate::dns::forwarder::HostsSnapshot,
    ) -> anyhow::Result<(
        Arc<crate::dns::forwarder::DnsForwarder>,
        Arc<crate::dns::upstream_pool::UpstreamPool>,
    )> {
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
                config.dns.strategy,
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
            .with_strategy(config.dns.strategy)
            .with_cache_enabled(config.dns.cache.enabled)
            .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_policy_id(dns_policy)
            .with_hosts_snapshot(hosts_snapshot),
        );
        Ok((forwarder, dns_upstream_pool))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(
        id: u128,
        name: &str,
        ua: Option<&str>,
    ) -> honk_config::subscription::Subscription {
        honk_config::subscription::Subscription {
            id: uuid::Uuid::from_u128(id),
            name: name.into(),
            url: "http://same-url".into(),
            user_agent: ua.map(str::to_string),
            ..Default::default()
        }
    }

    fn with_header(
        mut sub: honk_config::subscription::Subscription,
        value: &str,
    ) -> honk_config::subscription::Subscription {
        sub.headers = vec![honk_config::subscription::SubscriptionHeader {
            key: "X-Token".into(),
            value: value.into(),
        }];
        sub
    }

    fn subscription_node(name: &str, subscription_id: u128) -> honk_config::node::Node {
        honk_config::node::Node {
            name: name.into(),
            subscription_id: Some(uuid::Uuid::from_u128(subscription_id)),
            ..Default::default()
        }
    }

    #[test]
    fn rebase_matches_subscription_identity_beyond_url() {
        let current = Config {
            subscriptions: vec![
                subscription(1, "a", Some("ua-a")),
                subscription(2, "b", Some("ua-b")),
            ],
            nodes: vec![
                subscription_node("node-a", 1),
                subscription_node("node-b", 2),
            ],
            ..Default::default()
        };

        // Same file with the subscription order swapped; a fresh parse assigns
        // fresh IDs.
        let mut candidate = Config {
            subscriptions: vec![
                subscription(3, "b", Some("ua-b")),
                subscription(4, "a", Some("ua-a")),
            ],
            ..Default::default()
        };

        rebase_subscription_nodes(&current, &mut candidate);

        assert_eq!(candidate.subscriptions[0].id, uuid::Uuid::from_u128(2));
        assert_eq!(candidate.subscriptions[1].id, uuid::Uuid::from_u128(1));
        let mut node_names: Vec<&str> = candidate
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect();
        node_names.sort_unstable();
        assert_eq!(node_names, ["node-a", "node-b"]);
        for node in &candidate.nodes {
            let expected = if node.name == "node-a" { 1 } else { 2 };
            assert_eq!(node.subscription_id, Some(uuid::Uuid::from_u128(expected)));
        }
    }

    #[test]
    fn rebase_treats_changed_headers_as_a_new_subscription() {
        let current = Config {
            subscriptions: vec![with_header(subscription(1, "a", None), "old")],
            nodes: vec![subscription_node("node-a", 1)],
            ..Default::default()
        };
        let mut candidate = Config {
            subscriptions: vec![with_header(subscription(2, "a", None), "new")],
            ..Default::default()
        };

        rebase_subscription_nodes(&current, &mut candidate);

        assert_eq!(candidate.subscriptions[0].id, uuid::Uuid::from_u128(2));
        assert!(candidate.nodes.is_empty());
    }
}
