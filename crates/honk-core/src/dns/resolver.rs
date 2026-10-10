use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use honk_config::dns::DnsConfig;
use tokio::sync::Mutex;

use super::cache::DnsCache;
use super::forwarder::DnsForwarder;
use super::routing::DnsRouter;
use super::service::DnsService;
use super::upstream_pool::UpstreamPool;

#[derive(Debug, Clone)]
pub struct ResolvedAddr {
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
    pub min_ttl: u32,
}

pub struct DnsResolver {
    service: DnsService,
}

impl DnsResolver {
    pub fn new(config: &DnsConfig) -> anyhow::Result<Self> {
        let forwarder = build_forwarder_from_config(config)?;
        Ok(Self {
            service: DnsService::with_forwarder(forwarder),
        })
    }

    pub fn with_forwarder(
        config: &DnsConfig,
        forwarder: Arc<DnsForwarder>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            service: DnsService::with_forwarder(Arc::new(
                forwarder
                    .as_ref()
                    .clone()
                    .with_strategy(config.strategy)
                    .with_policy_from_config(config)?,
            )),
        })
    }

    pub(crate) fn with_service(service: DnsService) -> Self {
        Self { service }
    }

    pub fn forwarder(&self) -> Arc<DnsForwarder> {
        self.service.forwarder()
    }

    pub async fn resolve(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        self.service.resolve_name(domain).await
    }
    /// Resolve through configured DNS without a post-query bootstrap fallback.
    pub async fn resolve_without_fallback(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        self.service.resolve_name_without_fallback(domain).await
    }

    pub async fn resolve_for_source(
        &self,
        domain: &str,
        source: SocketAddr,
    ) -> anyhow::Result<ResolvedAddr> {
        self.service.resolve_name_for_source(domain, source).await
    }
}

fn build_forwarder_from_config(config: &DnsConfig) -> anyhow::Result<Arc<DnsForwarder>> {
    let dns_cache = Arc::new(Mutex::new(DnsCache::new(config.cache.max_size)));
    let requirements = DnsRouter::geo_requirements(config);
    let geo_sources = crate::routing::GeoSourceSet::load(&requirements);
    let router = Arc::new(DnsRouter::new_with_geo_sources(config, &geo_sources)?);
    let pool = Arc::new(
        UpstreamPool::new(&config.upstream, Arc::clone(&router))?
            .with_client_subnet(config.effective_client_subnet()?),
    );
    Ok(Arc::new(
        DnsForwarder::new(pool, dns_cache, router)
            .with_strategy(config.strategy)
            .with_cache_enabled(config.cache.enabled)
            .with_cache_ttl(config.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_stale_reply_ttl(config.cache.stale_reply_ttl)
            .with_policy_from_config(config)?,
    ))
}

#[cfg(test)]
mod tests;
