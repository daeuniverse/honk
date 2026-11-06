use super::*;
use crate::dns::forwarder::{HostsSnapshot, HostsSourceSet};
use crate::dns::policy::PolicyId;
use crate::dns::routing::DnsRouter;

pub(super) fn load_hosts_and_policy(
    config: &Config,
    dns_geo_fingerprint: &[u8; 32],
) -> Option<(HostsSourceSet, PolicyId)> {
    let hosts_sources = match HostsSourceSet::load(&config.dns) {
        Ok(sources) => sources,
        Err(error) => {
            warn!(target: "honk_core::control::reload::transaction", %error, "Failed to load DNS hosts snapshot");
            return None;
        }
    };
    let policy = match PolicyId::from_config_with_artifacts(
        &config.dns,
        &hosts_sources.fingerprint(),
        dns_geo_fingerprint,
    ) {
        Ok(policy) => policy,
        Err(error) => {
            warn!(target: "honk_core::control::reload::transaction", %error, "Failed to derive DNS policy identity");
            return None;
        }
    };
    Some((hosts_sources, policy))
}

pub(super) fn reuse_or_build_dns_router(
    current_config: &Config,
    new_config: &Config,
    current: Arc<DnsRouter>,
    dns_geo_fingerprint: [u8; 32],
    geo_sources: &crate::routing::GeoSourceSet,
    shared: &mut crate::routing::SharedMatchers,
) -> Option<Arc<DnsRouter>> {
    let reuse_dns_router = dns_routing_state_reusable(current_config, new_config)
        && current.geo_fingerprint() == dns_geo_fingerprint;
    if reuse_dns_router {
        Some(current)
    } else {
        match DnsRouter::new_sharing(&new_config.dns, geo_sources, shared) {
            Ok(router) => Some(Arc::new(router)),
            Err(error) => {
                warn!(target: "honk_core::control::reload::transaction", %error, "Failed to build DNS router");
                None
            }
        }
    }
}

pub(super) fn reuse_or_parse_hosts(
    hosts_sources: HostsSourceSet,
    current_hosts: HostsSnapshot,
) -> Option<HostsSnapshot> {
    let hosts_changed = hosts_sources.fingerprint() != current_hosts.fingerprint();
    if !hosts_changed {
        Some(current_hosts)
    } else {
        match hosts_sources.parse() {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                warn!(target: "honk_core::control::reload::transaction", %error, "Failed to parse DNS hosts snapshot");
                None
            }
        }
    }
}

impl ControlPlane {
    /// Build a DNS forwarder from an explicit config (used by the reload
    /// pipeline's build phase — must not read live state, so the caller can
    /// abort before commit without having mutated anything).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn build_dns_forwarder(
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
            .with_socket_budget(self.dns_socket_budget.clone())
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
            .with_socket_budget(self.dns_socket_budget.clone())
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_dns_forwarder_propagates_missing_external_ech_config() {
        use honk_config::node::{Node, OutboundConfig};
        use honk_config::types::NodeProtocol;

        let temp = tempfile::tempdir().unwrap();
        let ech_path = temp.path().join("ech-config");
        std::fs::write(&ech_path, "AA==").unwrap();

        let mut node = Node {
            name: "ech-node".into(),
            address: "127.0.0.1".into(),
            port: 443,
            outbound: OutboundConfig::from_protocol(NodeProtocol::AnyTLS),
            ..Default::default()
        };
        let anytls = node.anytls_mut().unwrap();
        anytls.password = Some("password".into());
        anytls.tls.enabled = true;
        anytls.tls.ech_config_path = Some(ech_path.to_string_lossy().into_owned());
        node.id = node.derive_id();

        let config = Config {
            nodes: vec![node],
            ..Default::default()
        };

        let dns_router =
            Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(&config.dns).unwrap());
        let initial_pool = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new(
                &config.dns.upstream,
                Arc::clone(&dns_router),
            )
            .unwrap(),
        );
        let initial_forwarder = Arc::new(crate::dns::forwarder::DnsForwarder::new(
            initial_pool,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                100,
            ))),
            Arc::clone(&dns_router),
        ));
        let traffic_router =
            Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
        let control_plane = crate::control::ControlPlane::new(
            config.clone(),
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            traffic_router.clone(),
            Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
            crate::dns::DnsResolver::new(&config.dns).unwrap(),
            initial_forwarder,
        )
        .unwrap();

        let source_registry = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap(),
        );
        let group_manager = Arc::new(GroupManager::new(&config.groups, &config.nodes));
        let hosts_snapshot = crate::dns::forwarder::HostsSourceSet::load(&config.dns)
            .unwrap()
            .parse()
            .unwrap();
        let dns_policy = crate::dns::policy::PolicyId::from_config_with_artifacts(
            &config.dns,
            &hosts_snapshot.fingerprint(),
            &dns_router.geo_fingerprint(),
        )
        .unwrap();

        std::fs::remove_file(&ech_path).unwrap();
        let result = control_plane
            .build_dns_forwarder(
                &config,
                Arc::new(traffic_router),
                group_manager,
                source_registry,
                dns_policy,
                dns_router,
                hosts_snapshot,
            )
            .await;

        let error = result
            .err()
            .expect("missing ECH file must reject preparation");
        let source = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .expect("preparation must preserve the file I/O error");
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn rebuilt_dns_generation_keeps_the_startup_socket_partition() {
        use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool, build_dns_query};
        use crate::dns::transport::DnsSocketBudget;
        use crate::dns::upstream_pool::UpstreamPool;
        use std::time::Duration;

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut wire = [0; 512];
            loop {
                let (length, peer) = server.recv_from(&mut wire).await.unwrap();
                wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                server.send_to(&wire[..length], peer).await.unwrap();
            }
        });
        let mut config = Config::default();
        config.dns.upstream = vec![honk_config::dns::DnsUpstream {
            name: "default".into(),
            address: address.to_string(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];
        let dns_router =
            Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(&config.dns).unwrap());
        let budget = DnsSocketBudget::new(1);
        let initial_pool = Arc::new(
            UpstreamPool::new(&config.dns.upstream, Arc::clone(&dns_router))
                .unwrap()
                .with_socket_budget(budget.clone()),
        );
        let forwarder = Arc::new(
            DnsForwarder::new(
                initial_pool.clone(),
                Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                    16,
                ))),
                Arc::clone(&dns_router),
            )
            .with_socket_budget(budget.clone()),
        );
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
        let control = ControlPlane::new_with_upstream_pool(
            config.clone(),
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router.clone(),
            Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
            forwarder,
            Arc::clone(&initial_pool),
        )
        .unwrap();
        let query = build_dns_query("reload-budget.test", 1);
        initial_pool.query("default", &query).await.unwrap();
        assert_eq!(budget.available_sockets(), 0);
        let hosts = HostsSourceSet::load(&config.dns).unwrap().parse().unwrap();
        let policy = PolicyId::from_config_with_artifacts(
            &config.dns,
            &hosts.fingerprint(),
            &dns_router.geo_fingerprint(),
        )
        .unwrap();
        let (_forwarder, rebuilt) = control
            .build_dns_forwarder(
                &config,
                Arc::new(router),
                Arc::new(GroupManager::new(&config.groups, &config.nodes)),
                Arc::new(
                    honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap(),
                ),
                policy,
                dns_router,
                hosts,
            )
            .await
            .unwrap();
        let mut blocked = Box::pin(rebuilt.query("default", &query));
        assert!(futures::poll!(blocked.as_mut()).is_pending());
        drop(blocked);
        assert_eq!(budget.available_sockets(), 0);
        initial_pool.close().await;
        tokio::time::timeout(Duration::from_secs(1), rebuilt.query("default", &query))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(budget.available_sockets(), 0);
        rebuilt.close().await;
        assert_eq!(budget.available_sockets(), 1);
        responder.abort();
        let _ = responder.await;
    }
}
