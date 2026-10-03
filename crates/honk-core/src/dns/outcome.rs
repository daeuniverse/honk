use bytes::Bytes;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::policy::PolicyId;
use super::response::ResponseTemplate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeStatus {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseClass {
    Positive,
    Nodata,
    Nxdomain,
    Servfail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    Fresh,
    Stale,
    Cache,
    Upstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveExpiry {
    ttl: Duration,
    cacheable: bool,
}

impl EffectiveExpiry {
    pub const fn cacheable(ttl: Duration) -> Self {
        Self {
            ttl,
            cacheable: true,
        }
    }

    pub const fn do_not_cache() -> Self {
        Self {
            ttl: Duration::ZERO,
            cacheable: false,
        }
    }

    pub const fn ttl(self) -> Duration {
        self.ttl
    }

    pub const fn is_cacheable(self) -> bool {
        self.cacheable
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "native-api", derive(serde::Serialize))]
pub(crate) enum RouteSource {
    #[default]
    #[cfg_attr(feature = "native-api", serde(rename = "default"))]
    Default,
    #[cfg_attr(feature = "native-api", serde(rename = "dns.routing"))]
    Routing,
    #[cfg_attr(feature = "native-api", serde(rename = "forced"))]
    Forced,
}

#[derive(Debug, Clone, Default)]
#[cfg(feature = "native-api")]
#[cfg_attr(feature = "native-api", derive(serde::Serialize))]
pub(crate) struct RequestRoute {
    pub(crate) source: RouteSource,
    pub(crate) rule: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsOutcome {
    status: OutcomeStatus,
    response_class: ResponseClass,
    provenance: Provenance,
    domain: Arc<str>,
    answer_ips: Vec<IpAddr>,
    expiry: EffectiveExpiry,
    logical_upstream: Option<String>,
    final_upstream: Option<String>,
    requery_history: Vec<String>,
    reusable: Bytes,
    rendered: Vec<u8>,
    template: Option<ResponseTemplate>,
    policy_id: Option<PolicyId>,
    #[cfg(feature = "native-api")]
    request_route: RequestRoute,
    #[cfg(feature = "native-api")]
    cache_entry_id: Option<String>,
}

pub(crate) struct OutcomeParts {
    pub status: OutcomeStatus,
    pub response_class: ResponseClass,
    pub provenance: Provenance,
    pub domain: Arc<str>,
    pub answer_ips: Vec<IpAddr>,
    pub expiry: EffectiveExpiry,
    pub logical_upstream: Option<String>,
    pub final_upstream: Option<String>,
    pub requery_history: Vec<String>,
    pub reusable: Bytes,
    pub rendered: Vec<u8>,
    pub template: Option<ResponseTemplate>,
    pub policy_id: Option<PolicyId>,
}

impl DnsOutcome {
    #[cfg(feature = "native-api")]
    pub(crate) fn client_error(
        query: &[u8],
        ingress: super::query::IngressProfile,
        rendered: Vec<u8>,
        source: RouteSource,
    ) -> Result<Self, Vec<u8>> {
        let Some(domain) = super::query::QueryContext::parse_with_profile(query, ingress)
            .ok()
            .and_then(|query| query.qname().and_then(|name| name.to_domain_name()))
        else {
            return Err(rendered);
        };
        Ok(Self::new(OutcomeParts {
            status: OutcomeStatus::Rejected,
            response_class: super::engine::classify_response(&rendered),
            provenance: Provenance::Fresh,
            domain: domain.into(),
            answer_ips: Vec::new(),
            expiry: EffectiveExpiry::do_not_cache(),
            logical_upstream: None,
            final_upstream: None,
            requery_history: Vec::new(),
            reusable: Bytes::copy_from_slice(&rendered),
            rendered,
            template: None,
            policy_id: None,
        })
        .with_route(source))
    }

    pub(crate) fn new(parts: OutcomeParts) -> Self {
        Self {
            status: parts.status,
            response_class: parts.response_class,
            provenance: parts.provenance,
            expiry: parts.expiry,
            logical_upstream: parts.logical_upstream,
            domain: parts.domain,
            answer_ips: parts.answer_ips,
            final_upstream: parts.final_upstream,
            requery_history: parts.requery_history,
            reusable: parts.reusable,
            rendered: parts.rendered,
            template: parts.template,
            policy_id: parts.policy_id,
            #[cfg(feature = "native-api")]
            request_route: RequestRoute::default(),
            #[cfg(feature = "native-api")]
            cache_entry_id: None,
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn request_route(&self) -> &RequestRoute {
        &self.request_route
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn cache_entry_id(&self) -> Option<&str> {
        self.cache_entry_id.as_deref()
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn with_route(mut self, source: RouteSource) -> Self {
        self.request_route.source = source;
        self
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn with_cache_entry_id(mut self, id: Option<String>) -> Self {
        self.cache_entry_id = id;
        self
    }

    pub const fn status(&self) -> OutcomeStatus {
        self.status
    }

    pub const fn response_class(&self) -> ResponseClass {
        self.response_class
    }

    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }

    /// Answered from the cache, fresh or stale, rather than an upstream exchange.
    pub const fn is_cached(&self) -> bool {
        matches!(self.provenance, Provenance::Cache | Provenance::Stale)
    }

    pub const fn expiry(&self) -> EffectiveExpiry {
        self.expiry
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn answer_ips(&self) -> &[IpAddr] {
        &self.answer_ips
    }

    pub fn logical_upstream(&self) -> Option<&str> {
        self.logical_upstream.as_deref()
    }

    pub fn final_upstream(&self) -> Option<&str> {
        self.final_upstream.as_deref()
    }

    pub fn requery_history(&self) -> &[String] {
        &self.requery_history
    }

    pub fn reusable(&self) -> &[u8] {
        &self.reusable
    }

    pub fn rendered(&self) -> &[u8] {
        &self.rendered
    }

    pub(crate) fn into_rendered(self) -> Vec<u8> {
        self.rendered
    }

    pub const fn template(&self) -> Option<&ResponseTemplate> {
        self.template.as_ref()
    }

    pub const fn policy_id(&self) -> Option<&PolicyId> {
        self.policy_id.as_ref()
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn metadata_for_test(
        status: OutcomeStatus,
        response_class: ResponseClass,
        provenance: Provenance,
        expiry: EffectiveExpiry,
        logical_upstream: &str,
        final_upstream: &str,
        history: &[&str],
        answer_ips: Vec<IpAddr>,
        rendered: Vec<u8>,
    ) -> Self {
        let query = crate::dns::forwarder::build_dns_query("example.com", 1);
        let context = crate::dns::query::QueryContext::parse(&query).expect("valid test query");
        let mut response = query.clone();
        response[2] |= 0x80;
        let template =
            ResponseTemplate::validate(&context, &response).expect("valid test response");
        Self::new(OutcomeParts {
            status,
            response_class,
            provenance,
            expiry,
            domain: "example.com".into(),
            answer_ips,
            logical_upstream: Some(logical_upstream.to_owned()),
            final_upstream: Some(final_upstream.to_owned()),
            requery_history: history.iter().map(ToString::to_string).collect(),
            reusable: response.into(),
            rendered,
            template: Some(template),
            policy_id: None,
        })
    }
}

#[cfg(test)]
mod tests;
