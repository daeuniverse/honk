use super::*;
use crate::config_diagnostics::DiagnosticUpdate;

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

pub(crate) fn rebase_subscription_nodes(
    current: &Config,
    candidate: &mut Config,
) -> std::collections::HashSet<uuid::Uuid> {
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
    let mut retained_providers = std::collections::HashSet::new();

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
                retained_providers.insert(previous.id);
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
    retained_providers
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
    /// failures leave the current generation untouched; an eBPF publication
    /// failure retains the active plan without replay. SIGHUP,
    /// subscription merges, and public callers share this serialized path.
    pub(in crate::control) async fn apply_runtime_config(
        &self,
        mut new_config: Config,
        diagnostics: crate::config_diagnostics::DiagnosticBuckets,
        drain: &DrainTracker,
    ) -> ReloadOutcome {
        let _reload = self.reload_lock.lock().await;
        crate::dns::ecs::resolve_client_subnet(&mut new_config.dns).await;
        let update = DiagnosticUpdate::Replace(diagnostics);
        match self
            .apply_resolved_runtime_config_locked(
                new_config,
                drain,
                update,
                None,
                #[cfg(feature = "native-api")]
                None,
            )
            .await
        {
            Ok(applied) => applied,
            Err(error) => {
                crate::report_runtime_admission_error(&error);
                ReloadOutcome::Rejected
            }
        }
    }
    pub(in crate::control) async fn apply_sighup_config(
        &self,
        mut new_config: Config,
        diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
        drain: &DrainTracker,
        authorizations: &mut crate::subscription::SubscriptionAuthorizations,
        #[cfg(feature = "native-api")] sources: Option<&crate::configuration::SourceUpdate>,
        #[cfg(feature = "native-api")] expected_group_revision: Option<&str>,
    ) -> Result<ReloadOutcome, honk_config::error::DetailedConfigError> {
        let _reload = self.reload_lock.lock().await;
        #[cfg(feature = "native-api")]
        if let Some(expected) = expected_group_revision
            && self
                .configuration
                .as_ref()
                .and_then(|configuration| configuration.revision())
                .as_deref()
                != Some(expected)
        {
            return Ok(ReloadOutcome::Rejected);
        }
        let current_guard = self.config.read().await;
        let current = Arc::clone(&current_guard);
        let retained_providers = rebase_subscription_nodes(&current, &mut new_config);
        drop(current_guard);
        crate::dns::ecs::resolve_client_subnet(&mut new_config.dns).await;
        let declared = new_config
            .subscriptions
            .iter()
            .filter(|subscription| retained_providers.contains(&subscription.id))
            .filter_map(|subscription| {
                Some((subscription.id, subscription.source.as_ref()?.0.clone()))
            })
            .collect();
        self.apply_resolved_runtime_config_locked(
            new_config,
            drain,
            DiagnosticUpdate::Rebase {
                static_diagnostics: diagnostics,
                retained_provider_ids: retained_providers,
                declared,
            },
            Some(authorizations),
            #[cfg(feature = "native-api")]
            sources,
        )
        .await
    }

    /// Validate and publish an explicit runtime configuration through the serialized
    /// transaction used by SIGHUP and subscription refreshes.
    ///
    /// Operator-document restrictions apply here, not to provider nodes admitted by
    /// subscription merges. Direct callers cannot reconcile process-owned workers;
    /// use SIGHUP to add, remove, or change subscription worker specifications.
    ///
    /// The supplied diagnostics are the candidate's full provenance and replace
    /// the active provenance only when the candidate is committed.
    pub async fn reload_runtime_config(
        &self,
        new_config: Config,
        diagnostics: crate::config_diagnostics::DiagnosticBuckets,
    ) -> bool {
        // A candidate equal to the admitted active configuration has already
        // passed exactly these checks; re-deriving 512 node identities on an
        // identical SIGHUP is the cost the reload benchmark guards against.
        let unchanged = *self.config.read().await.as_ref() == new_config;
        if !unchanged && let Err(error) = new_config.validate_detailed() {
            crate::report_runtime_admission_error(&error);
            return false;
        }
        let drain = Arc::clone(&self.drain_tracker);
        self.apply_runtime_config(new_config, diagnostics, &drain)
            .await
            .accepted()
    }

    pub(in crate::control) async fn apply_resolved_runtime_config_locked(
        &self,
        mut new_config: Config,
        drain: &DrainTracker,
        diagnostic_update: DiagnosticUpdate,
        authorizations: Option<&mut crate::subscription::SubscriptionAuthorizations>,
        #[cfg(feature = "native-api")] sources: Option<&crate::configuration::SourceUpdate>,
    ) -> Result<ReloadOutcome, honk_config::error::DetailedConfigError> {
        #[cfg(feature = "native-api")]
        let native = self.native.clone();
        #[cfg(feature = "native-api")]
        let _reloading = native
            .as_deref()
            .map(crate::observe::Observation::begin_reload);
        #[cfg(feature = "native-api")]
        let replaces_sources = matches!(
            &diagnostic_update,
            DiagnosticUpdate::Replace(_) | DiagnosticUpdate::Rebase { .. }
        );
        if let DiagnosticUpdate::Replace(buckets) = &diagnostic_update
            && buckets.providers.len() > 1
        {
            let mut provider_ids =
                std::collections::HashSet::with_capacity(buckets.providers.len());
            if buckets
                .providers
                .iter()
                .any(|(id, _)| !provider_ids.insert(*id))
            {
                error!("reload rejected: duplicate provider diagnostic buckets");
                return Ok(ReloadOutcome::Rejected);
            }
        }
        if let Err(error) =
            crate::subscription::validate_subscription_ids(&new_config.subscriptions)
        {
            error!(%error, "reload rejected: invalid subscription ids");
            return Ok(ReloadOutcome::Rejected);
        }
        let current_router = self.router.read().await.clone();
        let current_config = self.config.read().await.clone();
        #[cfg(feature = "native-api")]
        let prepared_sources = sources.and_then(|sources| {
            self.configuration
                .as_ref()
                .map(|configuration| configuration.prepare_accept(sources))
        });
        if authorizations.is_none()
            && !crate::subscription::same_subscription_worker_set(
                &current_config.subscriptions,
                &new_config.subscriptions,
            )
        {
            error!("reload rejected: subscription worker changes require the control command path");
            return Ok(ReloadOutcome::Rejected);
        }
        // Same proof as at the public entry: equality with the admitted active
        // configuration is admission. Anything else is verified before any shortcut.
        if new_config != *current_config.as_ref() {
            new_config.validate_assembled()?;
        }

        let config_unchanged = effective_config_unchanged(current_config.as_ref(), &mut new_config);
        #[cfg(feature = "native-api")]
        let prepared_catalog = self
            .native
            .as_ref()
            .map(|native| native.catalog.prepare(&new_config));
        let current_dns_forwarder = self.dns_controller.forwarder();
        let current_dns_router = current_dns_forwarder.routing_snapshot();
        #[cfg(feature = "native-api")]
        let supplied_geo_sources = sources.and_then(|sources| sources.geo_sources.as_ref());
        if config_unchanged && self.is_datapath_healthy() {
            let traffic_geo = current_router.geo_requirements();
            let dns_geo = current_dns_router.geo_requirements_snapshot();
            #[cfg(feature = "native-api")]
            let probed_geo_sources;
            #[cfg(feature = "native-api")]
            let geo_probe = match supplied_geo_sources {
                Some(sources) => sources,
                None => {
                    probed_geo_sources =
                        crate::routing::GeoSourceSet::probe_union(traffic_geo, dns_geo);
                    &probed_geo_sources
                }
            };
            #[cfg(not(feature = "native-api"))]
            let geo_probe = crate::routing::GeoSourceSet::probe_union(traffic_geo, dns_geo);
            let traffic_geo_fingerprint = geo_probe.fingerprint_for(traffic_geo);
            let dns_geo_fingerprint = geo_probe.fingerprint_for(dns_geo);
            let hosts_fingerprint =
                match crate::dns::forwarder::HostsSourceSet::probe_fingerprint(&new_config.dns) {
                    Ok(fingerprint) => fingerprint,
                    Err(error) => {
                        error!(%error, "Failed to fingerprint DNS hosts snapshot");
                        self.stop_reload_rejection_if_healthy(drain);
                        return Ok(ReloadOutcome::Rejected);
                    }
                };
            if current_router.geo_fingerprint() == traffic_geo_fingerprint
                && current_dns_router.geo_fingerprint() == dns_geo_fingerprint
                && current_dns_forwarder.policy_id().is_some_and(|policy| {
                    policy.matches_artifacts(&hosts_fingerprint, &dns_geo_fingerprint)
                })
            {
                let mut config = self.config.write().await;
                #[cfg(feature = "native-api")]
                if let Some(prepared) = &prepared_sources
                    && self
                        .configuration
                        .as_ref()
                        .is_some_and(|configuration| !configuration.can_accept(prepared))
                {
                    return Ok(ReloadOutcome::Rejected);
                }
                #[cfg(feature = "native-api")]
                if replaces_sources && let Some(flags) = &self.datapath_flags {
                    let mut mode = flags.publication().await;
                    let mut backend = self.ebpf.write().await;
                    if let Err(error) = mode.reset_for_activation(backend.as_mut()) {
                        error!(%error, "reload rejected: runtime mode reset failed");
                        return Ok(ReloadOutcome::Rejected);
                    }
                }
                let generation = self.diagnostics.read().generation;
                if !matches!(&diagnostic_update, DiagnosticUpdate::Preserve) {
                    self.diagnostics.write().buckets.apply(diagnostic_update);
                    #[cfg(feature = "native-api")]
                    if let Some(native) = &self.native {
                        native
                            .catalog
                            .install_prepared(prepared_catalog.expect("native candidate catalog"));
                    }
                }
                #[cfg(feature = "native-api")]
                if let Some(configuration) = &self.configuration {
                    if let Some(prepared) = prepared_sources {
                        configuration.accept(prepared, generation);
                    } else if replaces_sources {
                        configuration.invalidate();
                    }
                }
                #[cfg(feature = "native-api")]
                if let Some(owner) = &self.native_owner
                    && replaces_sources
                {
                    owner.activate(&new_config);
                }
                if declaring_sources_replaced(current_config.as_ref(), &new_config) {
                    *config = Arc::new(new_config);
                }
                info!("Configuration unchanged — retaining active runtime generation");
                return Ok(ReloadOutcome::Noop { generation });
            }
        }
        let restart_required =
            restart_required_fields(&current_config, &new_config, &self.log_files);
        if !restart_required.is_empty() {
            error!(
                fields = ?restart_required.iter().map(|field| field.path).collect::<Vec<_>>(),
                "reload rejected: changed fields require process restart"
            );
            return Ok(ReloadOutcome::Rejected);
        }

        #[cfg(feature = "reload-bench-counters")]
        self.reload_slow_path_entries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let traffic_geo = crate::routing::GeoRequirements::for_traffic(&new_config.routing.rules);
        let dns_geo = crate::dns::routing::DnsRouter::geo_requirements(&new_config.dns);
        #[cfg(feature = "native-api")]
        let loaded_geo_sources;
        #[cfg(feature = "native-api")]
        let geo_sources = match supplied_geo_sources {
            Some(sources) => sources,
            None => {
                loaded_geo_sources =
                    crate::routing::GeoSourceSet::load(&traffic_geo.union(&dns_geo));
                &loaded_geo_sources
            }
        };
        #[cfg(not(feature = "native-api"))]
        let geo_requirements = traffic_geo.union(&dns_geo);
        #[cfg(not(feature = "native-api"))]
        let geo_sources = &crate::routing::GeoSourceSet::load(&geo_requirements);
        let traffic_geo_fingerprint = geo_sources.fingerprint_for(&traffic_geo);
        let dns_geo_fingerprint = geo_sources.fingerprint_for(&dns_geo);
        let hosts_sources = match crate::dns::forwarder::HostsSourceSet::load(&new_config.dns) {
            Ok(sources) => sources,
            Err(error) => {
                error!(%error, "Failed to load DNS hosts snapshot");
                self.stop_reload_rejection_if_healthy(drain);
                return Ok(ReloadOutcome::Rejected);
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
                return Ok(ReloadOutcome::Rejected);
            }
        };
        let old_plan = self.active_routing_plan.read().clone();
        let old_has_direct_marks = current_router.has_direct_marks();
        let reuse_routing_state = routing_state_reusable(&current_config, &new_config)
            && current_router.geo_fingerprint() == traffic_geo_fingerprint;
        // Build the candidate completely before mutating live state. Network lists
        // the live traffic router already holds keep its matchers, even when only
        // the DNS router rebuilds.
        let mut shared = crate::routing::SharedMatchers::default();
        shared.offer(current_router.ip_matchers());
        let new_router = if reuse_routing_state {
            current_router
        } else {
            match Router::from_config_sharing(&new_config.routing, geo_sources, &mut shared) {
                Ok(router) => router,
                Err(error) => {
                    error!(%error, "Failed to build new router");
                    self.stop_reload_rejection_if_healthy(drain);
                    return Ok(ReloadOutcome::Rejected);
                }
            }
        };
        let pinned_router = Arc::new(new_router.clone());
        let new_has_direct_marks = new_router.has_direct_marks();
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
                self.resource_budget.vless_carriers,
                new_config.experimental.native_api.enabled,
                Some(&self.runtime_registry.read()),
            ) {
                Ok((registry, reused)) => (Arc::new(registry), reused),
                Err(e) => {
                    error!("Failed to build runtime registry (reload aborted): {}", e);
                    self.stop_reload_rejection_if_healthy(drain);
                    return Ok(ReloadOutcome::Rejected);
                }
            };
        new_group_manager.bind_transport_quality(&new_runtime_registry);
        let reuse_dns_router = dns_routing_state_reusable(&current_config, &new_config)
            && current_dns_router.geo_fingerprint() == dns_geo_fingerprint;
        let dns_router = if reuse_dns_router {
            current_dns_router
        } else {
            match crate::dns::routing::DnsRouter::new_sharing(
                &new_config.dns,
                geo_sources,
                &mut shared,
            ) {
                Ok(router) => Arc::new(router),
                Err(error) => {
                    error!(%error, "Failed to build DNS router");
                    self.stop_reload_rejection_if_healthy(drain);
                    return Ok(ReloadOutcome::Rejected);
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
                    return Ok(ReloadOutcome::Rejected);
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
                return Ok(ReloadOutcome::Rejected);
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
                    return Ok(ReloadOutcome::Rejected);
                }
            }
        };
        let generation = crate::dns::runtime::RuntimeGeneration::new(
            self.dns_controller
                .runtime_provider()
                .current_generation()
                .get()
                .saturating_add(1),
        );
        #[cfg(feature = "native-api")]
        let prepared_dictionary = self.native.as_ref().and_then(|native| {
            crate::observe::flows::kernel::KernelTraceDictionary::prepare(
                &native.instance_id,
                generation.get(),
                &new_router,
                &new_config,
                &new_plan,
            )
        });
        let old_projection_snapshot = {
            let current = self.dns_controller.runtime_provider().current();
            Arc::clone(current.routing_projection())
        };
        let projection_snapshot = Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
            generation.get(),
            Arc::clone(&pinned_router),
        ));
        let new_runtime =
            crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
                generation,
                udp_query_limit: self.resource_budget.dns_slow_path,
                forwarder: Arc::clone(&new_dns_forwarder),
                routing_projection: Arc::clone(&projection_snapshot),
                outbound_runtime: Some(Arc::clone(&new_runtime_registry)),
                transport: new_upstream_pool,
            });
        #[cfg(feature = "native-api")]
        if let Some(identity) = &prepared_catalog {
            new_runtime.bind_flow_catalog(Arc::clone(identity));
        }

        let route_count = new_router.route_count();
        let datapath_flags = if let Some(handle) = self.datapath_flags.clone() {
            handle
        } else {
            if current_config.global.nfqueue_enable || new_config.global.nfqueue_enable {
                error!("datapath flags writer is unavailable during NFQUEUE reload");
                return Ok(ReloadOutcome::Rejected);
            }
            let mode_state = self.mode_state.clone().unwrap_or_else(|| {
                Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
                    "Rule", "Proxy",
                )))
            });
            let handle =
                crate::mode::DatapathFlagsHandle::new(Arc::clone(&self.ebpf), mode_state, None);
            if let Err(error) = handle.initialize(false, false).await {
                error!(%error, "failed to initialize reload-scoped datapath flags writer");
                return Ok(ReloadOutcome::Rejected);
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
            self.restore_datapath_flags_after_rejected_reload(&datapath_flags, drain)
                .await;
            return Ok(ReloadOutcome::Rejected);
        }
        drain.start_rejecting();
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.cancel_all().await;
        }
        if !self.udp_pool.cancel_initializers_and_wait().await {
            warn!("UDP initializers did not drain before reload commit");
            self.restore_datapath_flags_after_rejected_reload(&datapath_flags, drain)
                .await;
            return Ok(ReloadOutcome::Rejected);
        }
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.wait_empty().await;
        }
        if !self.udp_pool.wait_for_retirements().await {
            warn!("UDP endpoint retirements did not drain before reload commit");
            self.restore_datapath_flags_after_rejected_reload(&datapath_flags, drain)
                .await;
            return Ok(ReloadOutcome::Rejected);
        }
        #[cfg(feature = "native-api")]
        let mut mode_reset_failed = false;
        let old_registry_result = {
            let mut router_guard = self.router.write().await;
            let mut config_guard = self.config.write().await;
            #[cfg(feature = "native-api")]
            let mut mode_publication = if replaces_sources {
                Some(datapath_flags.publication().await)
            } else {
                None
            };
            let mut ebpf = self.ebpf.write().await;
            let projection_publication = self.dns_controller.prepare_projection_publication();
            let mut group_guard = self.group_manager.write();
            let mut outbound_guard = self.outbound_id_map.write();
            let mut plan_guard = self.active_routing_plan.write();
            let mut runtime_guard = self.runtime_registry.write();
            'publication: {
                #[cfg(feature = "native-api")]
                if let Some(prepared) = &prepared_sources
                    && self
                        .configuration
                        .as_ref()
                        .is_some_and(|configuration| !configuration.can_accept(prepared))
                {
                    break 'publication Err(());
                }
                let old_connectivity = group_connectivity_snapshot(
                    &current_config,
                    &old_group_manager,
                    &self.alive_set,
                );
                let new_connectivity =
                    group_connectivity_snapshot(&new_config, &new_group_manager, &self.alive_set);
                let old_projection = projection_publication.project(&old_projection_snapshot);
                let new_projection = projection_publication.project(&projection_snapshot);
                // Recover a degraded runtime with a complete generation before reopening admission.
                let routing_publication_needed = !self.is_datapath_healthy()
                    || !old_plan.semantically_eq(&new_plan)
                    || !old_projection
                        .iter()
                        .map(|(ip, bitmap)| (ip, &bitmap.bitmap))
                        .eq(new_projection
                            .iter()
                            .map(|(ip, bitmap)| (ip, &bitmap.bitmap)));
                drop(old_projection);
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
                    let mut new_domain_routes = new_projection
                        .iter()
                        .map(|(ip, bitmap)| (crate::ebpf::maps::ip_addr_to_lpm_key(*ip), *bitmap))
                        .collect::<Vec<_>>();
                    new_domain_routes
                        .sort_unstable_by_key(|(key, _)| crate::ebpf::maps::lpm_key_bytes(key));
                    if let Err(error) = ebpf.publish_routing_plan(&new_plan, &new_domain_routes) {
                        match publish_group_connectivity(ebpf.as_mut(), &old_connectivity) {
                            Ok(()) => error!(
                                %error,
                                "Compiled routing publication failed; active generation retained"
                            ),
                            Err(restore_error) => {
                                error!(
                                    %error,
                                    %restore_error,
                                    "Routing publication rejected but health restoration failed"
                                );
                                self.datapath_healthy
                                    .store(false, std::sync::atomic::Ordering::Release);
                                self.drain_tracker.start_rejecting();
                                drain.start_rejecting();
                            }
                        }
                        break 'publication Err(());
                    }
                }
                #[cfg(feature = "native-api")]
                if let Some(mode) = &mut mode_publication
                    && let Err(error) = mode.reset_for_activation(ebpf.as_mut())
                {
                    error!(%error, "configuration committed but runtime mode reset failed");
                    mode_reset_failed = true;
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
                install_interrupt_callback(
                    &new_group_manager,
                    &new_config.groups,
                    &self.connection_tracker,
                    &self.diagnostics,
                    generation.get(),
                    #[cfg(feature = "native-api")]
                    self.native.as_ref(),
                );
                install_selector_warm_callback(&new_group_manager, &self.selector_warm_notify);
                if let Some(ref db) = self.cache_db {
                    let db_cb = Arc::clone(db);
                    new_group_manager.set_persist_callback(Some(Arc::new(
                        move |group, network, member| {
                            db_cb.save_network_selector(group, network, member);
                        },
                    )));
                }
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
                crate::ebpf::record_pname_routing(&router_guard, &**ebpf, &self.degradations);
                *config_guard = Arc::new(new_config);
                match &self.quic_score_target {
                    Some(target) => {
                        target.set_needed(crate::control::probers::needs_quic_probe(&config_guard))
                    }
                    None => crate::control::probers::report_quic_probe_restart(
                        &self.degradations,
                        &config_guard,
                    ),
                }
                {
                    let mut active_diagnostics = self.diagnostics.write();
                    #[cfg(feature = "native-api")]
                    let previous_generation = active_diagnostics.generation;
                    active_diagnostics.generation = generation.get();
                    #[cfg(feature = "native-api")]
                    if let Some(configuration) = &self.configuration {
                        if let Some(prepared) = prepared_sources {
                            configuration.accept(prepared, generation.get());
                        } else if replaces_sources {
                            configuration.invalidate();
                        }
                    }
                    active_diagnostics.buckets.apply(diagnostic_update);
                    #[cfg(feature = "native-api")]
                    if let Some(native) = &self.native {
                        self.alive_set.invalidate_group_health_observations();
                        if replaces_sources && let Some(owner) = &self.native_owner {
                            owner.activate(&config_guard);
                        }
                        native.committed(
                            prepared_catalog.expect("native candidate catalog"),
                            previous_generation,
                            generation.get(),
                        );
                    }
                }
                if let Some(authorizations) = authorizations {
                    authorizations
                        .publish(&current_config.subscriptions, &config_guard.subscriptions);
                }
                *group_guard = Arc::clone(&new_group_manager);
                *outbound_guard = new_outbound_id_map;
                if routing_publication_needed {
                    *plan_guard = Arc::clone(&new_plan);
                    #[cfg(feature = "native-api")]
                    if let Some(dictionary) = prepared_dictionary {
                        ebpf.bind_kernel_trace_dictionary(dictionary);
                    }
                }
                // The projection worker takes eBPF before its generation fence;
                // publish under both locks so an old batch cannot enter this snapshot.
                projection_publication.commit(
                    projection_snapshot,
                    routing_publication_needed.then_some(new_projection),
                );
                Ok(old_registry)
            }
        };
        let old_registry = match old_registry_result {
            Ok(old_registry) => old_registry,
            Err(()) => {
                self.restore_datapath_flags_after_rejected_reload(&datapath_flags, drain)
                    .await;
                return Ok(ReloadOutcome::Rejected);
            }
        };
        if !old_plan.semantically_eq(&new_plan) && (old_has_direct_marks || new_has_direct_marks) {
            // Direct sockets retain their policy mark for life, including raw DNS.
            self.udp_pool
                .remove_by_node(honk_config::config::DIRECT_NODE_ID);
        }

        honk_outbound::bootstrap::set_global(bootstrap_resolver);
        self.alive_set.set_direct_check_addr(direct_target);
        // No new generation-owned work may start on the old snapshot. Its
        // DNS runtime still owns it until old leases and transports retire;
        // only then do the pools enter graceful session drain.
        old_registry.begin_retirement();
        self.connection_pool
            .retire_generation(old_registry.generation());
        self.stop_udp_warm_coordinator().await;
        self.stop_selector_warm_coordinator().await;
        #[cfg(feature = "native-api")]
        if mode_reset_failed {
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return Ok(ReloadOutcome::CommittedDegraded {
                generation: generation.get(),
            });
        }
        self.start_udp_warm_coordinator(Arc::clone(&new_runtime_registry))
            .await;
        self.start_selector_warm_coordinator(new_runtime_registry)
            .await;
        {
            let config = self.config.read().await;
            let _ = sync_health_check_nodes(&self.alive_set, &config);
            self.alive_set
                .sync_urltest_groups(&urltest_group_registrations(&config));
            self.alive_set
                .sync_group_check_urls(&group_check_url_registrations(&config));
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
            return Ok(ReloadOutcome::CommittedDegraded {
                generation: generation.get(),
            });
        }
        info!("Configuration applied — {} routes active", route_count);
        #[cfg(feature = "ebpf")]
        if !reuse_routing_state {
            self.warn_lan_self_protection().await;
        }

        // A completed slow path has republished everything a latch could
        // have torn; re-arm.
        self.datapath_healthy
            .store(true, std::sync::atomic::Ordering::Release);
        self.stop_reload_rejection_if_healthy(drain);
        Ok(ReloadOutcome::Committed {
            generation: generation.get(),
        })
    }

    async fn restore_datapath_flags_after_rejected_reload(
        &self,
        datapath_flags: &crate::mode::DatapathFlagsHandle,
        drain: &DrainTracker,
    ) {
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
            .with_timeouts(
                std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
                std::time::Duration::from_millis(config.global.connect_timeout_ms),
            )
            // Same SharedGroupManager + traffic Router cells as the data path
            // (dae: Route DNS server IP; explicit `-> tag` still forces a group).
            .with_group_manager_snapshot(group_manager)
            .with_traffic_router_snapshot(router),
        );
        dns_upstream_pool.set_runtime_generation(runtime_generation)?;
        let forwarder = Arc::new(
            crate::dns::forwarder::DnsForwarder::new(
                Arc::clone(&dns_upstream_pool) as Arc<dyn crate::dns::forwarder::DnsUpstreamPool>,
                self.dns_controller.cache().await,
                dns_router,
            )
            .with_configured_upstreams(&config.dns)
            .with_timeouts(
                std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
                std::time::Duration::from_millis(config.global.connect_timeout_ms),
            )
            .with_strategy(config.dns.strategy)
            .with_cache_enabled(config.dns.cache.enabled)
            .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_stale_reply_ttl(config.dns.cache.stale_reply_ttl)
            .with_policy_id(dns_policy)
            .with_hosts_snapshot(hosts_snapshot),
        );
        Ok((forwarder, dns_upstream_pool))
    }
}

#[cfg(test)]
mod tests;
