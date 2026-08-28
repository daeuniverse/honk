//! DNS forwarding engine that combines caching, routing, and upstream
//! querying into a single resolution pipeline.
//!
//! The forwarder accepts raw DNS wire-format queries, routes them to
//! the appropriate upstream based on domain matching, caches responses,
//! and returns the result.  It also supports background prefetch to
//! warm the cache for frequently-accessed domains.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{Mutex, OnceCell};

use super::cache::{DnsCache, DnsCacheService};
use super::engine::{DnsEngine, EngineError};
use super::policy::PolicyId;
use super::response::ResponseError;
use super::routing::DnsRouter;
use honk_config::dns::{DnsConfig, DnsStrategy};

/// Abstraction over a pool of DNS upstream servers.
///
/// Implementations are expected to maintain connections to multiple
/// DNS upstreams and route raw queries to the named upstream.
#[async_trait]
pub trait DnsUpstreamPool: Send + Sync {
    /// Send a raw DNS query to the named upstream and return the
    /// raw wire-format response.
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[derive(Debug, Error)]
pub enum DnsForwardError {
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error("DNS exchange with upstream '{upstream}' failed: {source}")]
    Exchange {
        upstream: String,
        #[source]
        source: anyhow::Error,
    },
    #[error(transparent)]
    Response(#[from] ResponseError),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error("rejected DNS request escaped the request-plan branch")]
    RejectedPlanEscaped,
    #[error("DNS singleflight admission is saturated")]
    Overloaded,
}

#[derive(Debug, Error)]
enum AsIsExchangeError {
    #[error("create asis UDP socket: {source}")]
    Socket {
        #[source]
        source: std::io::Error,
    },
    #[error("configure asis UDP socket as nonblocking: {source}")]
    Nonblocking {
        #[source]
        source: std::io::Error,
    },
    #[error("apply asis UDP bypass mark: {source}")]
    BypassMark {
        #[source]
        source: std::io::Error,
    },
    #[error("bind asis UDP socket: {source}")]
    Bind {
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ResolveMode {
    Strict,
    Compatibility,
}

/// DNS query pipeline: strategy and request routing, exact-identity cache,
/// upstream exchange, bounded response re-query, TTL policy, then cache write.
/// Domain-route learning is owned by `DnsController`'s outcome projection.
#[derive(Clone)]
pub struct DnsForwarder {
    pub(crate) upstream_pool: Arc<dyn DnsUpstreamPool>,
    pub(crate) cache: Arc<Mutex<DnsCache>>,
    cache_service: Arc<OnceCell<Arc<DnsCacheService>>>,
    engine: Arc<OnceCell<DnsEngine>>,
    pub(crate) routing: Arc<DnsRouter>,
    pub(crate) strategy: DnsStrategy,
    hosts: Option<Arc<hosts::HostsFile>>,
    hosts_fingerprint: [u8; 32],
    /// When false, skip positive/negative cache lookups and inserts
    /// (`dns.optimistic_cache` / `cache.enabled`).
    pub(crate) cache_enabled: bool,
    /// Fixed positive-cache TTL in seconds (`dns.optimistic_cache_ttl` /
    /// `cache.ttl`). Overrides answer-section min TTL when storing entries
    /// and when rewriting wire TTLs on the way into the cache. `0` falls
    /// back to the answer min TTL (default path uses 600).
    pub(crate) cache_ttl: u32,
    pub(crate) policy_id: Option<PolicyId>,
    pub(crate) query_timeout: Duration,
    pub(crate) dial_timeout: Duration,
    prefetch_tasks: Arc<prefetch::PrefetchTasks>,
}

impl DnsForwarder {
    /// Create a new forwarder with the given upstream pool, cache, and router.
    pub fn new(
        upstream_pool: Arc<dyn DnsUpstreamPool>,
        cache: Arc<Mutex<DnsCache>>,
        routing: Arc<DnsRouter>,
    ) -> Self {
        Self {
            upstream_pool,
            cache,
            cache_service: Arc::new(OnceCell::new()),
            engine: Arc::new(OnceCell::new()),
            routing,
            strategy: DnsStrategy::default(),
            hosts: None,
            hosts_fingerprint: hosts::HostsSnapshot::default().fingerprint(),
            cache_enabled: true,
            // 0 = keep answer min TTL until `with_cache_ttl` is applied from config.
            cache_ttl: 0,
            policy_id: None,
            query_timeout: Duration::from_secs(5),
            dial_timeout: Duration::from_secs(10),
            prefetch_tasks: prefetch::PrefetchTasks::new(),
        }
    }

    /// Set the IP-version strategy used for DNS responses.
    pub fn with_strategy(mut self, strategy: DnsStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Enable or disable the in-memory DNS cache (dae `optimistic_cache`).
    pub fn with_cache_enabled(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Set the fixed positive-cache TTL (dae `optimistic_cache_ttl`).
    ///
    /// When non-zero, this value **overrides** the minimum TTL from the
    /// upstream answer for both cache lifetime and wire-format TTL fields
    /// stored in the cache. `0` keeps answer min TTL behaviour.
    pub fn with_cache_ttl(mut self, ttl_secs: u32) -> Self {
        self.cache_ttl = ttl_secs;
        self
    }

    /// Set the DNS exchange and TCP dial timeouts.
    pub fn with_timeouts(mut self, query_timeout: Duration, dial_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self.dial_timeout = dial_timeout;
        self
    }

    pub fn with_policy_id(mut self, policy_id: PolicyId) -> Self {
        if self.policy_id.as_ref() != Some(&policy_id) {
            self.engine = Arc::new(OnceCell::new());
        }
        self.policy_id = Some(policy_id);
        self
    }

    pub fn with_policy_from_config(self, config: &DnsConfig) -> anyhow::Result<Self> {
        let sources = hosts::HostsSourceSet::load(config)?;
        let policy_id = PolicyId::from_config_with_artifacts(
            config,
            &sources.fingerprint(),
            &self.routing.geo_fingerprint(),
        )
        .context("failed to derive effective DNS policy identity")?;
        let snapshot = sources.parse().map_err(anyhow::Error::new)?;
        Ok(self.with_policy_id(policy_id).with_hosts_snapshot(snapshot))
    }

    #[cfg(test)]
    pub(crate) fn with_hosts_from_config(self, config: &DnsConfig) -> anyhow::Result<Self> {
        let sources = hosts::HostsSourceSet::load(config)?;
        let snapshot = sources.parse().map_err(anyhow::Error::new)?;
        Ok(self.with_hosts_snapshot(snapshot))
    }

    pub(crate) fn hosts_snapshot(&self) -> hosts::HostsSnapshot {
        hosts::HostsSnapshot::new(self.hosts_fingerprint, self.hosts.clone())
    }

    pub(crate) fn with_hosts_snapshot(mut self, snapshot: hosts::HostsSnapshot) -> Self {
        self.hosts_fingerprint = snapshot.fingerprint();
        self.hosts = snapshot.hosts();
        self
    }

    pub(crate) fn routing_snapshot(&self) -> Arc<DnsRouter> {
        Arc::clone(&self.routing)
    }

    /// Cache identity for this forwarder's effective config and loaded artifacts.
    pub fn policy_id(&self) -> Option<PolicyId> {
        self.policy_id.clone()
    }

    /// Return a clone of the underlying cache Arc.
    pub fn cache(&self) -> Arc<Mutex<DnsCache>> {
        self.cache.clone()
    }

    pub(crate) async fn cache_service(&self) -> Arc<DnsCacheService> {
        Arc::clone(
            self.cache_service
                .get_or_init(|| async { self.cache.lock().await.service() })
                .await,
        )
    }

    pub(crate) async fn engine(&self) -> Result<&DnsEngine, EngineError> {
        self.engine
            .get_or_try_init(|| async {
                DnsEngine::from_shared_router(Arc::clone(&self.routing), self.policy_id.clone())
            })
            .await
    }

    fn background_clone(&self) -> Self {
        Self {
            upstream_pool: Arc::clone(&self.upstream_pool),
            cache: Arc::clone(&self.cache),
            cache_service: Arc::clone(&self.cache_service),
            engine: Arc::clone(&self.engine),
            routing: Arc::clone(&self.routing),
            strategy: self.strategy,
            hosts: self.hosts.clone(),
            hosts_fingerprint: self.hosts_fingerprint,
            cache_enabled: self.cache_enabled,
            cache_ttl: self.cache_ttl,
            policy_id: self.policy_id.clone(),
            query_timeout: self.query_timeout,
            dial_timeout: self.dial_timeout,
            prefetch_tasks: prefetch::PrefetchTasks::closed(),
        }
    }

    pub(crate) async fn shutdown_prefetch(&self) {
        self.prefetch_tasks.shutdown().await;
    }
}

mod exchange;
mod hosts;
pub(crate) use hosts::{HostsSnapshot, HostsSourceSet};
mod message {
    use crate::dns::query::{NameParseState, parse_name};
    use std::net::{IpAddr, SocketAddr};

    use super::AsIsExchangeError;

    pub(super) fn new_asis_socket_with_mark(
        destination: SocketAddr,
        mark: impl FnOnce(&socket2::Socket) -> std::io::Result<()>,
    ) -> Result<socket2::Socket, AsIsExchangeError> {
        let domain = if destination.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)
            .map_err(|source| AsIsExchangeError::Socket { source })?;
        socket
            .set_nonblocking(true)
            .map_err(|source| AsIsExchangeError::Nonblocking { source })?;
        mark(&socket).map_err(|source| AsIsExchangeError::BypassMark { source })?;
        let bind_address = SocketAddr::new(
            if destination.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            },
            0,
        );
        socket
            .bind(&bind_address.into())
            .map_err(|source| AsIsExchangeError::Bind { source })?;
        Ok(socket)
    }

    /// Build a minimal DNS query for the given domain and query type.
    pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let qname = encode_dns_name(domain);
        let mut query = Vec::with_capacity(12 + qname.len() + 4);

        // Header: ID=0, flags=0x0100 (RD), QDCOUNT=1, rest=0
        query.extend_from_slice(&[0x00, 0x00]); // ID
        query.extend_from_slice(&[0x01, 0x00]); // Flags (recursion desired)
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        query.extend_from_slice(&qname);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        query
    }

    /// Encode a domain name into DNS label format.
    ///
    /// Example: `"example.com"` → `[0x07, b'e', ..., 0x03, b'c', b'o', b'm', 0x00]`
    fn encode_dns_name(domain: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for label in domain.split('.') {
            if label.len() > 63 {
                continue;
            }
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }
        encoded.push(0x00); // terminator
        encoded
    }

    /// Parse the first question from a raw DNS query.
    ///
    /// Returns the domain name and QTYPE on success, or `None` if the
    /// message is truncated or malformed.
    pub fn parse_dns_question(data: &[u8]) -> Option<(String, u16)> {
        if data.len() < 16 || u16::from_be_bytes([data[4], data[5]]) == 0 {
            return None;
        }

        let mut state = NameParseState::new(data.len());
        let (name, question_end) = parse_name(data, 12, &mut state).ok()?;
        let fields_end = question_end.checked_add(4)?;
        let fields = data.get(question_end..fields_end)?;
        let qtype = u16::from_be_bytes([fields[0], fields[1]]);
        Some((name.to_domain_name()?, qtype))
    }

    /// Extract A/AAAA answer IPs from a wire-format DNS response.
    pub fn extract_answer_ips(data: &[u8]) -> Vec<IpAddr> {
        crate::dns::wire::extract_ips_from_dns_response(data)
    }
}
mod prefetch;
mod resolution;
mod response {
    use std::net::IpAddr;

    use super::message::extract_answer_ips;
    use crate::dns::query::QueryContext;
    use crate::dns::response::dns_error_flags;
    use honk_config::dns::DnsStrategy;

    /// Return `true` if the given query type is hard-filtered at request time.
    /// Only the `*_only` strategies filter here; prefer strategies forward both
    /// families and suppress at response time instead.
    pub(crate) fn is_filtered_qtype(qtype: u16, strategy: &DnsStrategy) -> bool {
        match strategy {
            DnsStrategy::Ipv4Only => qtype == 28, // AAAA
            DnsStrategy::Ipv6Only => qtype == 1,  // A
            DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 | DnsStrategy::Both => false,
        }
    }

    /// Whether a wire-format response contains at least one address record of
    /// the given family (qtype 1 = A, 28 = AAAA).
    pub(super) fn response_has_family_ips(response: &[u8], qtype: u16) -> bool {
        extract_answer_ips(response).iter().any(|ip| match qtype {
            1 => ip.is_ipv4(),
            28 => ip.is_ipv6(),
            _ => false,
        })
    }

    /// Human-readable qtype name for logging.
    pub(crate) fn qtype_name(qtype: u16) -> &'static str {
        match qtype {
            1 => "A",
            28 => "AAAA",
            5 => "CNAME",
            15 => "MX",
            16 => "TXT",
            2 => "NS",
            _ => "OTHER",
        }
    }

    /// Build a NODATA response while preserving the exact question bytes.
    pub(crate) fn make_empty_response(raw_query: &[u8], query: &QueryContext) -> Vec<u8> {
        make_address_response(raw_query, query, &[], 0)
    }

    pub(super) fn make_address_response(
        raw_query: &[u8],
        query: &QueryContext,
        addresses: &[IpAddr],
        ttl: u32,
    ) -> Vec<u8> {
        let question_end = query
            .question_offsets()
            .map(|offsets| offsets.end())
            .unwrap_or(12)
            .min(raw_query.len());
        let mut response = Vec::with_capacity(
            question_end
                .saturating_add(addresses.len().saturating_mul(28))
                .saturating_add(11),
        );
        response.extend_from_slice(&raw_query[..question_end]);
        response.resize(response.len().max(12), 0);
        response[2..4].copy_from_slice(&dns_error_flags(raw_query, 0).to_be_bytes());
        response[4..6].copy_from_slice(&1u16.to_be_bytes());
        response[6..12].fill(0);

        let qtype = query.qtype().map(|value| value.get()).unwrap_or_default();
        let question_offset = query
            .question_offsets()
            .and_then(|offsets| u16::try_from(offsets.start()).ok())
            .filter(|offset| *offset <= 0x3fff)
            .unwrap_or(12);
        let name_pointer = (0xc000 | question_offset).to_be_bytes();
        let mut answer_count = 0u16;
        for address in addresses {
            if answer_count == u16::MAX {
                break;
            }
            match (qtype, address) {
                (1, IpAddr::V4(address)) => {
                    append_address_record(&mut response, name_pointer, 1, ttl, &address.octets());
                }
                (28, IpAddr::V6(address)) => {
                    append_address_record(&mut response, name_pointer, 28, ttl, &address.octets());
                }
                _ => continue,
            }
            answer_count += 1;
        }
        response[6..8].copy_from_slice(&answer_count.to_be_bytes());

        if let Some(edns) = query.edns().filter(|edns| edns.version() == 0) {
            response[10..12].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0, 0, 41]);
            response.extend_from_slice(&edns.advertised_size().to_be_bytes());
            let flags = if edns.dnssec_ok() { 0x8000u32 } else { 0 };
            response.extend_from_slice(&flags.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
        }
        response
    }

    fn append_address_record(
        response: &mut Vec<u8>,
        name_pointer: [u8; 2],
        record_type: u16,
        ttl: u32,
        address: &[u8],
    ) {
        response.extend_from_slice(&name_pointer);
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        let rdlength = if record_type == 1 { 4u16 } else { 16u16 };
        response.extend_from_slice(&rdlength.to_be_bytes());
        response.extend_from_slice(address);
    }
}
mod strategy {
    use anyhow::Context;
    use bytes::Bytes;

    use tracing::debug;

    use crate::dns::query::{DnsRequestMeta, QueryContext};
    use honk_config::dns::DnsStrategy;

    use super::response::{make_empty_response, qtype_name, response_has_family_ips};
    use super::{DnsForwarder, ResolveMode};

    impl DnsForwarder {
        /// Prefer-mode strategy (sing-box / dae `ipversion_prefer` semantics):
        /// when the preferred family has answers for the same name, suppress the
        /// non-preferred family's response with NODATA; otherwise return it
        /// unchanged. Only-modes are handled earlier at request time.
        pub(crate) async fn apply_prefer_strategy(
            &self,
            raw_query: &[u8],
            query: &QueryContext,
            qtype: u16,
            response: Bytes,
            metadata: DnsRequestMeta,
            mode: ResolveMode,
        ) -> anyhow::Result<Bytes> {
            let preferred = match (&self.strategy, qtype) {
                (DnsStrategy::PreferIpv4, 28) => 1u16,
                (DnsStrategy::PreferIpv6, 1) => 28u16,
                _ => return Ok(response),
            };
            if self
                .preferred_family_has_answers(raw_query, query, preferred, metadata, mode)
                .await?
            {
                debug!(
                    qtype = qtype_name(qtype),
                    preferred_qtype = qtype_name(preferred),
                    "DNS forwarder suppressed non-preferred address family"
                );
                return Ok(make_empty_response(raw_query, query).into());
            }
            Ok(response)
        }

        /// Whether the preferred address family has answers for the same query,
        /// issuing a sibling query through the normal pipeline. Only the first
        /// question's QTYPE changes, preserving the caller's complete wire profile.
        async fn preferred_family_has_answers(
            &self,
            raw_query: &[u8],
            query: &QueryContext,
            preferred_qtype: u16,
            metadata: DnsRequestMeta,
            mode: ResolveMode,
        ) -> anyhow::Result<bool> {
            let offsets = query
                .question_offsets()
                .context("preferred-family probe is missing question offsets")?;
            let qtype_start = offsets
                .end()
                .checked_sub(4)
                .context("preferred-family question offsets are invalid")?;
            let qtype_end = qtype_start + 2;
            let mut sibling_query = raw_query.to_vec();
            sibling_query
                .get_mut(qtype_start..qtype_end)
                .context("preferred-family QTYPE lies outside the query")?
                .copy_from_slice(&preferred_qtype.to_be_bytes());

            // Boxed: breaks the async recursion cycle through resolve_with_context
            // (the sibling uses the preferred qtype, so it never re-enters here).
            let sibling = Box::pin(self.resolve_inner(
                &sibling_query,
                metadata,
                query.ingress(),
                false,
                mode,
            ))
            .await;
            Ok(match sibling {
                Ok(outcome) => response_has_family_ips(outcome.rendered(), preferred_qtype),
                Err(_) => {
                    debug!(
                        error_kind = "preferred_family_probe_failed",
                        preferred_qtype, "DNS forwarder preferred-family probe failed"
                    );
                    false
                }
            })
        }
    }
}
mod ttl;

#[cfg(test)]
use message::new_asis_socket_with_mark;
pub use message::{build_dns_query, extract_answer_ips, parse_dns_question};
pub(crate) use response::{is_filtered_qtype, make_empty_response};
#[cfg(test)]
use ttl::effective_cache_ttl;
pub(crate) use ttl::{
    SERVE_STALE_TTL_SECS, extract_min_ttl, extract_soa_negative_ttl, rewrite_answer_ttls,
    traversal_strings,
};

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use crate::dns::query::{DnsRequestMeta, IngressProfile};

    include!("forwarder/tests/fixtures.rs");
    include!("forwarder/tests/service_flush.rs");
    include!("forwarder/tests/singleflight.rs");
    include!("forwarder/tests/stale_refresh.rs");
    include!("forwarder/tests/cache_routing.rs");
    include!("forwarder/tests/wire_helpers.rs");
    include!("forwarder/tests/rule_pipeline.rs");
    include!("forwarder/tests/requery_singleflight.rs");
    include!("forwarder/tests/context_and_family.rs");
    include!("forwarder/tests/family_and_negative.rs");
    include!("forwarder/tests/asis_transport.rs");
}
