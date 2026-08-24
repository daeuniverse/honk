use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;

use super::cache::KeyIdentity;
use super::outcome::ResponseClass;
use super::planner::{
    PlanError, Planner, RequestContext, RequestPlan, RequestScope, ResponseContext, ResponsePlan,
    ResponseTraversal, UpstreamTag,
};
use super::policy::PolicyId;
use super::query::{DnsRequestMeta, IngressProfile, QueryContext, QueryError};
use super::response::{ResponseError, ResponseTemplate};
use super::routing::DnsRouter;

mod metadata {
    use std::time::Duration;

    use crate::dns::outcome::{EffectiveExpiry, ResponseClass};

    pub(crate) fn classify_response(wire: &[u8]) -> ResponseClass {
        let rcode = wire.get(3).copied().unwrap_or_default() & 0x0f;
        match rcode {
            2 => ResponseClass::Servfail,
            3 => ResponseClass::Nxdomain,
            _ if wire.get(6..8) == Some(&[0, 0]) => ResponseClass::Nodata,
            _ => ResponseClass::Positive,
        }
    }

    pub(crate) fn effective_expiry(
        fixed_ttl: Option<u32>,
        configured_ttl: u32,
        answer_ttl: u32,
    ) -> EffectiveExpiry {
        match fixed_ttl {
            Some(0) => EffectiveExpiry::do_not_cache(),
            Some(ttl) => EffectiveExpiry::cacheable(Duration::from_secs(u64::from(ttl))),
            None if configured_ttl > 0 => {
                EffectiveExpiry::cacheable(Duration::from_secs(u64::from(configured_ttl)))
            }
            None => EffectiveExpiry::cacheable(Duration::from_secs(u64::from(answer_ttl.max(1)))),
        }
    }
}
pub(crate) mod pipeline;

pub(crate) use metadata::{classify_response, effective_expiry};

pub(crate) struct DnsEngine {
    planner: Planner,
    policy_id: Option<PolicyId>,
}

pub(crate) struct PreparedQuery {
    query: QueryContext,
    key_identity: KeyIdentity,
    domain: Arc<str>,
    qtype: u16,
    plan: RequestPlan,
}

pub(crate) struct ParsedQuery {
    query: QueryContext,
    domain: Arc<str>,
    qtype: u16,
}

pub(crate) struct AnalyzedResponse {
    pub wire: Vec<u8>,
    pub class: ResponseClass,
    pub answer_ips: Vec<IpAddr>,
    pub strict_reusable: bool,
}

pub(crate) enum ResponseDirective {
    Accept {
        response: AnalyzedResponse,
        traversal: ResponseTraversal,
    },
    Reject {
        response: AnalyzedResponse,
        traversal: ResponseTraversal,
    },
    Requery {
        upstream: UpstreamTag,
        traversal: ResponseTraversal,
        strict_reusable: bool,
    },
}

impl DnsEngine {
    pub(crate) fn from_router(
        router: &DnsRouter,
        policy_id: Option<PolicyId>,
    ) -> Result<Self, EngineError> {
        let upstreams = router
            .upstream_names()
            .into_iter()
            .map(|name| UpstreamTag::new(&name))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            planner: Planner::new(router.clone(), upstreams),
            policy_id,
        })
    }

    #[cfg(test)]
    pub(crate) fn prepare(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> Result<PreparedQuery, EngineError> {
        let parsed = Self::parse_query(raw_query, ingress)?;
        self.prepare_parsed(parsed, metadata, false)
    }

    pub(crate) fn parse_query(
        raw_query: &[u8],
        ingress: IngressProfile,
    ) -> Result<ParsedQuery, EngineError> {
        let query = QueryContext::parse_with_profile(raw_query, ingress)?;
        if query.questions().len() > 1 {
            return Err(EngineError::MultipleQuestions);
        }
        let domain: Arc<str> = query
            .qname()
            .ok_or(EngineError::MissingQuestion)?
            .to_domain_name()
            .ok_or(EngineError::MalformedCanonicalName)?
            .into();
        let qtype = query.qtype().ok_or(EngineError::MissingQuestion)?.get();
        Ok(ParsedQuery {
            query,
            domain,
            qtype,
        })
    }

    pub(crate) fn prepare_parsed(
        &self,
        parsed: ParsedQuery,
        metadata: DnsRequestMeta,
        compatibility: bool,
    ) -> Result<PreparedQuery, EngineError> {
        let ParsedQuery {
            query,
            domain,
            qtype,
        } = parsed;
        let context = RequestContext {
            domain: &domain,
            qtype,
            metadata,
        };
        let plan = match self.planner.plan_request(context) {
            Err(PlanError::MissingOriginalDestination) if compatibility => {
                RequestPlan::Exchange(RequestScope::Upstream(UpstreamTag::new("default")?))
            }
            result => result?,
        };
        Ok(PreparedQuery {
            key_identity: KeyIdentity::new(&query, self.policy_id.clone()),
            query,
            domain,
            qtype,
            plan,
        })
    }

    pub(crate) fn analyze(
        &self,
        prepared: &PreparedQuery,
        traversal: ResponseTraversal,
        wire: Vec<u8>,
        strict: bool,
    ) -> Result<ResponseDirective, EngineError> {
        let truncated = super::response::is_truncated(&wire);
        let strict_reusable = if strict {
            ResponseTemplate::check(&prepared.query, &wire)?;
            !truncated
        } else {
            ResponseTemplate::check(&prepared.query, &wire).is_ok() && !truncated
        };
        let class = classify_response(&wire);
        if matches!(class, ResponseClass::Nxdomain | ResponseClass::Servfail) {
            return Ok(ResponseDirective::Accept {
                response: AnalyzedResponse {
                    wire,
                    class,
                    answer_ips: Vec::new(),
                    strict_reusable,
                },
                traversal,
            });
        }
        let answer_ips = if truncated {
            Vec::new()
        } else {
            super::forwarder::extract_answer_ips(&wire)
        };
        let current_traversal = traversal.clone();
        let planned = self.planner.plan_response(
            ResponseContext {
                domain: &prepared.domain,
                qtype: prepared.qtype,
                answer_ips: &answer_ips,
            },
            traversal,
        );
        let mut response = AnalyzedResponse {
            wire,
            class,
            answer_ips,
            strict_reusable,
        };
        let plan = match planned {
            Err(PlanError::UpstreamCycle { .. } | PlanError::DepthExceeded { .. }) if !strict => {
                response.strict_reusable = false;
                return Ok(ResponseDirective::Accept {
                    response,
                    traversal: current_traversal,
                });
            }
            result => result?,
        };
        Ok(match plan {
            ResponsePlan::Accept => ResponseDirective::Accept {
                response,
                traversal: current_traversal,
            },
            ResponsePlan::Reject => ResponseDirective::Reject {
                response,
                traversal: current_traversal,
            },
            ResponsePlan::Requery {
                upstream,
                traversal,
            } => ResponseDirective::Requery {
                upstream,
                traversal,
                strict_reusable: response.strict_reusable,
            },
        })
    }

    pub(crate) const fn policy_id(&self) -> Option<&PolicyId> {
        self.policy_id.as_ref()
    }
}

impl ParsedQuery {
    pub(crate) const fn query(&self) -> &QueryContext {
        &self.query
    }

    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn domain_arc(&self) -> Arc<str> {
        Arc::clone(&self.domain)
    }

    pub(crate) const fn qtype(&self) -> u16 {
        self.qtype
    }
}

impl PreparedQuery {
    pub(crate) const fn query(&self) -> &QueryContext {
        &self.query
    }

    pub(crate) fn cache_key(
        &self,
        scope: RequestScope,
        operation: crate::dns::cache::OperationKind,
    ) -> crate::dns::cache::CacheKey {
        self.key_identity.key(scope, operation)
    }

    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn domain_arc(&self) -> Arc<str> {
        Arc::clone(&self.domain)
    }

    pub(crate) const fn qtype(&self) -> u16 {
        self.qtype
    }

    pub(crate) const fn plan(&self) -> &RequestPlan {
        &self.plan
    }

    pub(crate) const fn is_cacheable(&self) -> bool {
        self.query.is_cacheable()
    }

    pub(crate) const fn is_coalescable(&self) -> bool {
        self.query.is_coalescable()
    }
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("DNS query parse failed: {0}")]
    Query(#[from] QueryError),
    #[error("DNS request has no question")]
    MissingQuestion,
    #[error("DNS requests with multiple questions are unsupported")]
    MultipleQuestions,
    #[error("DNS canonical question name is malformed")]
    MalformedCanonicalName,
    #[error("DNS planning failed: {0}")]
    Plan(#[from] PlanError),
    #[error("DNS response validation failed: {0}")]
    Response(#[from] ResponseError),
}

#[cfg(test)]
mod tests;
