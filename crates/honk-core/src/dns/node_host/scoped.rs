use super::*;
use crate::dns::{
    forwarder::{
        DnsForwarder, DnsUpstreamPool, HostsSnapshot, NodeHostAlias, build_dns_query,
        extract_answer_ips,
    },
    runtime::{DnsRuntime, RuntimeTransport},
    transport::DnsSocketBudget,
    upstream_pool::UpstreamPool,
};
use futures::{StreamExt, stream::FuturesUnordered};
use honk_config::dns::{DnsStrategy, DnsUpstream};
#[cfg(test)]
use honk_config::node::Node;
use std::collections::HashSet;
use std::sync::Weak;

#[derive(Clone)]
struct ClaimPolicy {
    tags: Vec<String>,
    imported: Option<Arc<honk_config::subscription::dns::SubscriptionDns>>,
}

struct NodePolicy {
    claim: ClaimPolicy,
    pool: Option<Arc<UpstreamPool>>,
}

pub(crate) struct ScopedDns {
    nodes: HashMap<uuid::Uuid, NodePolicy>,
    main: Arc<UpstreamPool>,
    pools: Vec<Arc<UpstreamPool>>,
    bootstrap: Option<honk_outbound::bootstrap::BootstrapResolver>,
    strategy: DnsStrategy,
}

pub(crate) fn resolution_changed(
    a: &Config,
    b: &Config,
    hosts_changed: bool,
) -> HashSet<uuid::Uuid> {
    let common_changed = hosts_changed
        || a.dns != b.dns
        || a.global.bootstrap_resolver != b.global.bootstrap_resolver;
    b.nodes
        .iter()
        .filter(|node| {
            let provider = |config: &Config| {
                config
                    .subscriptions
                    .iter()
                    .find(|s| Some(s.id) == node.subscription_id)
                    .map(|s| (s.name.clone(), s.imported_dns.clone()))
            };
            common_changed || provider(a) != provider(b)
        })
        .map(|node| node.id)
        .collect()
}

fn pool(
    config: &Config,
    upstreams: &[DnsUpstream],
    router: Arc<crate::dns::routing::DnsRouter>,
    budget: &DnsSocketBudget,
) -> anyhow::Result<UpstreamPool> {
    Ok(UpstreamPool::new_with_proxy_and_bootstrap(
        upstreams,
        router,
        None,
        Vec::new(),
        Vec::new(),
        honk_outbound::bootstrap::BootstrapResolver::parse(&config.global.bootstrap_resolver),
        config.dns.strategy,
    )
    .map_err(|_| anyhow::anyhow!("invalid imported subscription DNS upstream"))?
    .with_socket_budget(budget.clone())
    .with_timeouts(
        std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
        std::time::Duration::from_millis(config.global.connect_timeout_ms),
    ))
}

pub(crate) fn prepare(
    config: &Config,
    main: Arc<UpstreamPool>,
    router: Arc<crate::dns::routing::DnsRouter>,
    budget: &DnsSocketBudget,
) -> anyhow::Result<Arc<ScopedDns>> {
    let mut pools = Vec::new();
    let mut providers = HashMap::new();
    for sub in &config.subscriptions {
        let Some(dns) = sub
            .imported_dns
            .as_ref()
            .filter(|_| sub.import_dns && sub.enabled)
        else {
            continue;
        };
        let all = dns.unique_upstreams();
        let mut imported = pool(config, &all, Arc::clone(&router), budget)?;
        if !dns.default_nameservers.is_empty() {
            let bootstrap = Arc::new(pool(
                config,
                &dns.default_nameservers,
                Arc::clone(&router),
                budget,
            )?);
            let names = dns
                .default_nameservers
                .iter()
                .map(|u| u.name.clone())
                .collect();
            imported = imported.with_endpoint_bootstrap(Arc::new(BootstrapPool {
                pool: Arc::clone(&bootstrap),
                names,
            }));
            pools.push(bootstrap);
        }
        let imported = Arc::new(imported);
        pools.push(Arc::clone(&imported));
        providers.insert(sub.id, imported);
    }
    let nodes = config
        .nodes
        .iter()
        .map(|node| {
            let sub = config
                .subscriptions
                .iter()
                .find(|s| Some(s.id) == node.subscription_id);
            (
                node.id,
                NodePolicy {
                    claim: ClaimPolicy {
                        tags: sub.map(|s| vec![s.name.clone()]).unwrap_or_default(),
                        imported: sub
                            .filter(|s| s.import_dns && s.enabled)
                            .and_then(|s| s.imported_dns.clone()),
                    },
                    pool: sub.and_then(|s| providers.get(&s.id).cloned()),
                },
            )
        })
        .collect();
    Ok(Arc::new(ScopedDns {
        nodes,
        pools,
        main,
        bootstrap: honk_outbound::bootstrap::BootstrapResolver::parse(
            &config.global.bootstrap_resolver,
        ),
        strategy: config.dns.strategy,
    }))
}

#[async_trait::async_trait]
impl RuntimeTransport for ScopedDns {
    async fn close(&self) {
        self.main.close().await;
        for pool in &self.pools {
            pool.close().await;
        }
    }

    fn tasks_failed(&self) -> bool {
        self.main.tasks_failed() || self.pools.iter().any(|p| p.tasks_failed())
    }

    fn reap_idle_resources(&self) -> usize {
        self.main.reap_idle_resources()
            + self
                .pools
                .iter()
                .map(|p| p.reap_idle_resources())
                .sum::<usize>()
    }
}

struct Routing {
    runtime: Weak<DnsRuntime>,
    dns: Weak<ScopedDns>,
    hosts: HostsSnapshot,
    router: Arc<crate::dns::routing::DnsRouter>,
    claims: HashMap<uuid::Uuid, ClaimPolicy>,
    bootstrap: Option<honk_outbound::bootstrap::BootstrapResolver>,
}

pub(crate) fn bind(
    registry: &honk_outbound::runtime::OutboundRuntimeRegistry,
    runtime: &Arc<DnsRuntime>,
    dns: Arc<ScopedDns>,
) {
    let forwarder = runtime.forwarder();
    let claims = dns
        .nodes
        .iter()
        .map(|(&id, policy)| (id, policy.claim.clone()))
        .collect();
    registry.bind_node_resolver(Arc::new(Routing {
        runtime: Arc::downgrade(runtime),
        dns: Arc::downgrade(&dns),
        hosts: forwarder.hosts_snapshot(),
        router: forwarder.routing_snapshot(),
        claims,
        bootstrap: dns.bootstrap,
    }));
}

impl honk_outbound::bootstrap::NodeHostResolver for Routing {
    fn lookup(&self, _host: &str) -> Option<honk_outbound::bootstrap::NodeHostLookup> {
        None
    }

    fn fallback_bootstrap(&self) -> Option<honk_outbound::bootstrap::BootstrapResolver> {
        self.bootstrap
    }

    fn lookup_node(
        &self,
        node: uuid::Uuid,
        host: &str,
    ) -> Option<honk_outbound::bootstrap::NodeHostLookup> {
        let host = normalize(host);
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return None;
        }
        let is_claimed = self.claims.get(&node).is_some_and(|policy| {
            if self.hosts.is_alias(&host) {
                if self.runtime.upgrade().is_none() || self.dns.upgrade().is_none() {
                    not_instrumented();
                }
                return true;
            }
            if !policy.tags.is_empty() && self.router.has_node_rules() {
                not_instrumented();
                if self
                    .router
                    .select_node_upstream(&host, &policy.tags)
                    .is_some()
                {
                    return true;
                }
            }
            if let Some(imported) = &policy.imported {
                not_instrumented();
                if imported.select(&host).is_some() {
                    return true;
                }
            }
            false
        });
        if !is_claimed {
            return None;
        }
        let runtime = self.runtime.clone();
        let dns = self.dns.clone();
        Some(Box::pin(async move {
            let runtime = runtime.upgrade().ok_or_else(cancelled)?;
            let dns = dns.upgrade().ok_or_else(cancelled)?;
            let lease = DnsRuntime::try_acquire_active_or_leased(&runtime).ok_or_else(cancelled)?;
            let _query_permit = runtime.try_acquire_query().map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => {
                    io::Error::other(honk_outbound::proxy::PacketRejection::Capacity)
                }
                tokio::sync::TryAcquireError::Closed => cancelled(),
            })?;
            let future = dns.resolve(runtime.forwarder(), node, &host);
            let result = lease
                .run(std::pin::pin!(future))
                .await
                .map_err(|_| cancelled())?;
            result.map_err(to_io_error)
        }))
    }
}

fn normalize(host: &str) -> String {
    host.trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn cancelled() -> io::Error {
    io::Error::other(honk_outbound::proxy::PacketRejection::Cancelled)
}

fn to_io_error(error: anyhow::Error) -> io::Error {
    if let Some(rejection) = honk_outbound::proxy::packet_rejection(&error) {
        return io::Error::other(rejection);
    }
    io::Error::other(error)
}

fn not_instrumented() {
    use honk_outbound::runtime::flow_observation::{self, FlowEvent, GapReason};

    if let Some(observer) = flow_observation::current() {
        observer.publish(FlowEvent::Gap(GapReason::NotInstrumented));
    }
}

fn select_families(
    strategy: DnsStrategy,
    mut addresses: Vec<IpAddr>,
) -> anyhow::Result<Vec<IpAddr>> {
    addresses.retain(|ip| match strategy {
        DnsStrategy::Ipv4Only => ip.is_ipv4(),
        DnsStrategy::Ipv6Only => ip.is_ipv6(),
        _ => true,
    });
    if strategy == DnsStrategy::PreferIpv6 {
        addresses.sort_by_key(IpAddr::is_ipv4);
    }
    if addresses.is_empty() {
        anyhow::bail!("node DNS returned no addresses");
    }
    Ok(addresses)
}

impl ScopedDns {
    async fn resolve(
        &self,
        forwarder: &DnsForwarder,
        node: uuid::Uuid,
        host: &str,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let policy = &self.nodes[&node];
        let target;
        let host = match forwarder.node_host_alias(host)? {
            Some(NodeHostAlias::Addresses(addresses)) => {
                not_instrumented();
                return select_families(self.strategy, addresses);
            }
            Some(NodeHostAlias::Name(name)) => {
                target = name;
                &target
            }
            None => host,
        };
        let router = forwarder.routing_snapshot();
        if !policy.claim.tags.is_empty() && router.has_node_rules() {
            not_instrumented();
            if let Some(upstream) = router.select_node_upstream(host, &policy.claim.tags) {
                return resolve_pool(
                    &self.main,
                    &[upstream.to_owned()],
                    host,
                    self.strategy,
                    None,
                )
                .await;
            }
        }
        if let Some(imported) = &policy.claim.imported {
            not_instrumented();
            if let (Some(pool), Some(upstreams)) = (&policy.pool, imported.select(host)) {
                let names = upstreams.iter().map(|u| u.name.clone()).collect::<Vec<_>>();
                return resolve_pool(pool, &names, host, self.strategy, imported.ipv6).await;
            }
        }
        let addresses = honk_outbound::bootstrap::resolve_with(self.bootstrap, host).await?;
        select_families(self.strategy, addresses)
    }
}

struct BootstrapPool {
    pool: Arc<UpstreamPool>,
    names: Vec<String>,
}

impl std::fmt::Debug for BootstrapPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapPool")
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

impl crate::dns::endpoint::EndpointBootstrap for BootstrapPool {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<IpAddr>>> + Send + 'a>>
    {
        Box::pin(async move {
            resolve_pool(&self.pool, &self.names, host, DnsStrategy::Both, None).await
        })
    }
}

async fn batch(
    pool: &UpstreamPool,
    names: &[String],
    host: &str,
    qtype: u16,
) -> anyhow::Result<Vec<IpAddr>> {
    let query = build_dns_query(host, qtype);
    let context = crate::dns::query::QueryContext::parse(&query)?;
    let mut queries = names
        .iter()
        .map(|name| pool.query(name, &query))
        .collect::<FuturesUnordered<_>>();
    let mut error = anyhow::anyhow!("node DNS has no upstream");
    while let Some(result) = queries.next().await {
        match result {
            Ok(response) => {
                let rcode = crate::dns::response::ResponseTemplate::check(&context, &response)
                    .and_then(|()| crate::dns::response::response_rcode(&response));
                let rcode = match rcode {
                    Ok(rcode) => rcode,
                    Err(cause) => {
                        error = cause.into();
                        continue;
                    }
                };
                match rcode {
                    0 => return Ok(extract_answer_ips(&response)),
                    3 => return Ok(Vec::new()),
                    _ => {
                        error = anyhow::anyhow!("node DNS upstream returned rcode {rcode}");
                        continue;
                    }
                }
            }
            Err(cause) if honk_outbound::proxy::is_packet_rejection(&cause) => return Err(cause),
            Err(cause) => error = cause,
        }
    }
    Err(error)
}

async fn resolve_pool(
    pool: &UpstreamPool,
    names: &[String],
    host: &str,
    strategy: DnsStrategy,
    ipv6: Option<bool>,
) -> anyhow::Result<Vec<IpAddr>> {
    let v4 = async {
        if strategy != DnsStrategy::Ipv6Only {
            batch(pool, names, host, 1).await
        } else {
            Ok(Vec::new())
        }
    };
    let v6 = async {
        if strategy != DnsStrategy::Ipv4Only && ipv6 != Some(false) {
            batch(pool, names, host, 28).await
        } else {
            Ok(Vec::new())
        }
    };
    let (a, b) = tokio::join!(v4, v6);
    let a = match a {
        Err(error) if honk_outbound::proxy::is_packet_rejection(&error) => return Err(error),
        result => result,
    };
    let b = match b {
        Err(error) if honk_outbound::proxy::is_packet_rejection(&error) => return Err(error),
        result => result,
    };
    let (first, second) = if strategy == DnsStrategy::PreferIpv6 {
        (b, a)
    } else {
        (a, b)
    };
    let mut addresses = Vec::new();
    let mut error = None;
    for result in [first, second] {
        match result {
            Ok(ips) => addresses.extend(ips),
            Err(cause) => error = Some(cause),
        }
    }
    if addresses.is_empty() {
        return Err(error.unwrap_or_else(|| anyhow::anyhow!("node DNS returned no addresses")));
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests;
