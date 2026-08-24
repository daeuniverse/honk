use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use tracing::{debug, trace};

use crate::dns::cache::{CacheKey, DnsCacheService, PublicationEpoch};
use crate::dns::engine::{DnsEngine, ParsedQuery, PreparedQuery};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeParts, OutcomeStatus, Provenance};
use crate::dns::planner::RequestScope;
use crate::dns::query::{DnsRequestMeta, IngressProfile, QueryContext};
use crate::dns::response::ResponseTemplate;
use crate::dns::singleflight::FlightKey;
use honk_ebpf_common::DAE_BYPASS_MARK;

use super::message::{build_dns_query, new_asis_socket_with_mark};
use super::ttl::{SERVE_STALE_TTL_SECS, patch_txid, rewrite_answer_ttls};
use super::{DnsForwardError, DnsForwarder, ResolveMode};

impl DnsForwarder {
    pub(crate) async fn exchange(
        &self,
        scope: &RequestScope,
        raw_query: &[u8],
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        match scope {
            RequestScope::Upstream(upstream) => {
                self.upstream_pool.query(upstream.as_str(), raw_query).await
            }
            RequestScope::AsIs(destination) => {
                self.query_asis(raw_query, *destination, ingress).await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn outcome_from_wire(
        &self,
        engine: &DnsEngine,
        prepared: &PreparedQuery,
        reusable: impl Into<Bytes>,
        analyzed_answer_ips: Option<(usize, Vec<IpAddr>)>,
        status: OutcomeStatus,
        provenance: Provenance,
        expiry: EffectiveExpiry,
        logical_upstream: Option<String>,
        final_upstream: Option<String>,
        requery_history: Vec<String>,
        mode: ResolveMode,
    ) -> Result<DnsOutcome, DnsForwardError> {
        self.outcome_from_query(
            engine,
            prepared.query(),
            prepared.domain_arc(),
            reusable,
            analyzed_answer_ips,
            status,
            provenance,
            expiry,
            logical_upstream,
            final_upstream,
            requery_history,
            mode,
        )
    }

    pub(crate) fn local_outcome_from_wire(
        &self,
        engine: &DnsEngine,
        parsed: &ParsedQuery,
        reusable: impl Into<Bytes>,
        mode: ResolveMode,
    ) -> Result<DnsOutcome, DnsForwardError> {
        self.outcome_from_query(
            engine,
            parsed.query(),
            parsed.domain_arc(),
            reusable,
            None,
            OutcomeStatus::Accepted,
            Provenance::Fresh,
            EffectiveExpiry::do_not_cache(),
            None,
            None,
            Vec::new(),
            mode,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn outcome_from_query(
        &self,
        engine: &DnsEngine,
        query: &QueryContext,
        domain: Arc<str>,
        reusable: impl Into<Bytes>,
        analyzed_answer_ips: Option<(usize, Vec<IpAddr>)>,
        status: OutcomeStatus,
        provenance: Provenance,
        expiry: EffectiveExpiry,
        logical_upstream: Option<String>,
        final_upstream: Option<String>,
        requery_history: Vec<String>,
        mode: ResolveMode,
    ) -> Result<DnsOutcome, DnsForwardError> {
        let reusable = reusable.into();
        let template = match ResponseTemplate::validate_owned(query, reusable.clone()) {
            Ok(template) => Some(template),
            Err(_) if matches!(mode, ResolveMode::Compatibility) => None,
            Err(error) => return Err(error.into()),
        };
        let rendered = match &template {
            Some(template) => template.render(query)?,
            None => patch_txid(reusable.to_vec(), query.txid().get()),
        };
        let truncated = crate::dns::response::is_truncated(&reusable);
        let response_class = crate::dns::engine::classify_response(&reusable);
        let answer_ips = if !truncated
            && status == OutcomeStatus::Accepted
            && response_class == crate::dns::outcome::ResponseClass::Positive
        {
            match analyzed_answer_ips {
                Some((source_wire_len, ips)) if source_wire_len == rendered.len() => ips,
                _ => super::message::extract_answer_ips(&rendered),
            }
        } else {
            Vec::new()
        };
        Ok(DnsOutcome::new(OutcomeParts {
            status,
            response_class,
            provenance,
            domain,
            answer_ips,
            expiry,
            logical_upstream,
            final_upstream,
            requery_history,
            reusable,
            rendered,
            template,
            policy_id: engine.policy_id().cloned(),
        }))
    }

    /// RFC 8767 serve-stale: fall back to a recently-expired cache entry
    /// when the upstream phase fails. TTLs are rewritten to
    /// [`SERVE_STALE_TTL_SECS`] so the client re-asks soon, and the txid is
    /// patched to the caller's query.
    pub(crate) async fn try_serve_stale(
        &self,
        cache_key: &CacheKey,
        raw_query: &[u8],
        mode: ResolveMode,
    ) -> Option<Vec<u8>> {
        if !self.cache_enabled {
            return None;
        }
        let cache = self.cache_service().await;
        let entry = cache.get_stale_exact(cache_key, matches!(mode, ResolveMode::Strict))?;
        let mut response = entry.response.to_vec();
        rewrite_answer_ttls(&mut response, SERVE_STALE_TTL_SECS);
        if response.len() >= 2 && raw_query.len() >= 2 {
            response[0..2].copy_from_slice(&raw_query[0..2]);
        }
        debug!("DNS forwarder serving stale cache after upstream failure");
        Some(response)
    }

    /// Spawn a deduplicated background refresh for a hot entry nearing
    /// expiry (stale-while-revalidate). The refresh bypasses the cache read
    /// so it always reaches the upstream; the normal pipeline writes the
    /// fresh answer back.
    pub(crate) fn maybe_spawn_refresh(
        &self,
        cache: Arc<DnsCacheService>,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        mode: ResolveMode,
        flight_key: crate::dns::cache::CacheKey,
        publication_epoch: PublicationEpoch,
    ) {
        let ingress = flight_key.ingress();
        let crate::dns::singleflight::FlightRole::Leader(owner) =
            cache.singleflight().acquire(FlightKey::Refresh(flight_key))
        else {
            return;
        };
        let this = self.clone();
        let query = raw_query.to_vec();
        let spawned = cache.spawn_refresh(async move {
            let result = crate::dns::engine::pipeline::resolve_with_owner(
                &this,
                &query,
                metadata,
                ingress,
                true,
                mode,
                crate::dns::engine::pipeline::ResolveExecution::refresh(owner, publication_epoch),
            )
            .await;
            if result.is_err() {
                debug!(
                    error_kind = "background_refresh_failed",
                    "DNS background refresh failed"
                );
            }
        });
        if !spawned {
            debug!("DNS forwarder: refresh service is closed");
        }
    }

    /// Dial the original destination DNS server (dae `asis`).
    async fn query_asis(
        &self,
        raw_query: &[u8],
        destination: SocketAddr,
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        match ingress {
            IngressProfile::Udp { .. } => {
                let response = self.query_asis_udp(raw_query, destination).await?;
                if crate::dns::response::is_truncated(&response) {
                    debug!(
                        destination = %destination,
                        "DNS forwarder: truncated asis UDP response, retrying over TCP"
                    );
                    self.query_asis_tcp(raw_query, destination).await
                } else {
                    Ok(response)
                }
            }
            IngressProfile::Tcp => self.query_asis_tcp(raw_query, destination).await,
            IngressProfile::Api | IngressProfile::Internal => {
                unreachable!("internal/API asis request escaped planning")
            }
        }
    }

    async fn query_asis_udp(
        &self,
        raw_query: &[u8],
        destination: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        debug!(%destination, "DNS forwarder: asis UDP dial");
        let sock2 = new_asis_socket_with_mark(destination, |socket| {
            #[cfg(target_os = "linux")]
            {
                honk_outbound::util::set_mark_best_effort(socket, DAE_BYPASS_MARK)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = socket;
                Ok(())
            }
        })?;
        let socket = tokio::net::UdpSocket::from_std(sock2.into()).context("asis UDP from_std")?;
        socket
            .connect(destination)
            .await
            .context("asis UDP connect")?;

        tokio::time::timeout(self.query_timeout, async {
            socket.send(raw_query).await?;
            let mut response = vec![0u8; usize::from(u16::MAX)];
            let received = socket.recv(&mut response).await?;
            response.truncate(received);
            Ok::<_, std::io::Error>(response)
        })
        .await
        .context("asis UDP query timeout")?
        .context("asis UDP exchange")
    }

    async fn query_asis_tcp(
        &self,
        raw_query: &[u8],
        destination: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        debug!(%destination, "DNS forwarder: asis TCP dial");
        let mut stream = honk_outbound::util::connect_marked_addr(
            destination,
            Some(DAE_BYPASS_MARK),
            self.dial_timeout,
        )
        .await
        .context("asis TCP connect")?;
        crate::dns::transport::exchange_length_prefixed(&mut stream, raw_query, self.query_timeout)
            .await
            .context("asis TCP exchange")
    }

    /// Prefetch domains asynchronously to warm the cache.
    ///
    /// Constructs A-record queries for each domain and resolves them
    /// in background tasks.  Failures are silently ignored — the goal
    /// is best-effort cache warming.
    pub fn prefetch(&self, domains: &[String]) {
        for domain in domains {
            let domain = domain.clone();
            let query = build_dns_query(&domain, 1);
            let forwarder = self.background_clone();
            let _ = self.prefetch_tasks.spawn(async move {
                match forwarder
                    .resolve_with_profile(&query, IngressProfile::Internal)
                    .await
                {
                    Err(_) => {
                        debug!(error_kind = "prefetch_failed", "DNS prefetch failed");
                    }
                    _ => {
                        trace!("DNS prefetch cached successfully");
                    }
                }
            });
        }
    }
}
