use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::dns::query::DnsRequestMeta;
use crate::dns::routing::{DnsRequestDecision, DnsResponseDecision, DnsRouter};

pub const MAX_RESPONSE_UPSTREAMS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpstreamTag(Arc<str>);

impl UpstreamTag {
    pub fn new(value: &str) -> Result<Self, PlanError> {
        if value.is_empty() {
            return Err(PlanError::EmptyUpstream);
        }
        Ok(Self(Arc::from(value)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestScope {
    Upstream(UpstreamTag),
    AsIs(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestPlan {
    Reject,
    Exchange(RequestScope),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponsePlan {
    Accept,
    Reject,
    Requery {
        upstream: UpstreamTag,
        traversal: ResponseTraversal,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct RequestContext<'a> {
    pub domain: &'a str,
    pub qtype: u16,
    pub metadata: DnsRequestMeta,
}

#[derive(Debug, Clone, Copy)]
pub struct ResponseContext<'a> {
    pub domain: &'a str,
    pub qtype: u16,
    pub answer_ips: &'a [IpAddr],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseTraversal {
    path: Vec<UpstreamTag>,
    current: UpstreamTag,
    visited: BTreeSet<UpstreamTag>,
}

impl ResponseTraversal {
    pub fn start(upstream: UpstreamTag) -> Self {
        let visited = BTreeSet::from([upstream.clone()]);
        Self {
            path: vec![upstream.clone()],
            current: upstream,
            visited,
        }
    }

    pub fn from_path(path: impl IntoIterator<Item = UpstreamTag>) -> Result<Self, PlanError> {
        let mut iterator = path.into_iter();
        let first = iterator.next().ok_or(PlanError::EmptyTraversal)?;
        let mut traversal = Self::start(first);
        for upstream in iterator {
            traversal = traversal.advance(upstream)?;
        }
        Ok(traversal)
    }

    pub fn current(&self) -> &UpstreamTag {
        &self.current
    }

    pub fn path(&self) -> &[UpstreamTag] {
        &self.path
    }

    pub fn advance(mut self, upstream: UpstreamTag) -> Result<Self, PlanError> {
        if self.visited.contains(&upstream) {
            return Err(PlanError::UpstreamCycle { upstream });
        }
        if self.path.len() >= MAX_RESPONSE_UPSTREAMS {
            return Err(PlanError::DepthExceeded {
                max: MAX_RESPONSE_UPSTREAMS,
            });
        }
        self.visited.insert(upstream.clone());
        self.path.push(upstream.clone());
        self.current = upstream;
        Ok(self)
    }
}

pub struct Planner {
    router: Arc<DnsRouter>,
    upstreams: BTreeSet<UpstreamTag>,
}

impl Planner {
    pub fn new(router: impl Into<Arc<DnsRouter>>, upstreams: BTreeSet<UpstreamTag>) -> Self {
        Self {
            router: router.into(),
            upstreams,
        }
    }

    pub fn plan_request(&self, context: RequestContext<'_>) -> Result<RequestPlan, PlanError> {
        match self.router.select_request_normalized(
            context.domain,
            context.qtype,
            context.metadata.source_ip(),
        ) {
            DnsRequestDecision::Reject => Ok(RequestPlan::Reject),
            DnsRequestDecision::AsIs => context
                .metadata
                .original_dst()
                .map(|destination| RequestPlan::Exchange(RequestScope::AsIs(destination)))
                .ok_or(PlanError::MissingOriginalDestination),
            DnsRequestDecision::Upstream(name) => {
                let upstream = UpstreamTag::new(&name)?;
                self.require_known(&upstream)?;
                Ok(RequestPlan::Exchange(RequestScope::Upstream(upstream)))
            }
        }
    }

    pub fn plan_response(
        &self,
        context: ResponseContext<'_>,
        traversal: ResponseTraversal,
    ) -> Result<ResponsePlan, PlanError> {
        match self.router.select_response_normalized(
            context.domain,
            context.qtype,
            context.answer_ips,
            traversal.current().as_str(),
        ) {
            DnsResponseDecision::Accept => Ok(ResponsePlan::Accept),
            DnsResponseDecision::Reject => Ok(ResponsePlan::Reject),
            DnsResponseDecision::Requery(name) => {
                let upstream = UpstreamTag::new(&name)?;
                self.require_known(&upstream)?;
                let traversal = traversal.advance(upstream.clone())?;
                Ok(ResponsePlan::Requery {
                    upstream,
                    traversal,
                })
            }
        }
    }

    fn require_known(&self, upstream: &UpstreamTag) -> Result<(), PlanError> {
        if self.upstreams.contains(upstream) {
            Ok(())
        } else {
            Err(PlanError::UnknownUpstream {
                upstream: upstream.clone(),
            })
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("upstream tag is empty")]
    EmptyUpstream,
    #[error("as-is request has no original destination")]
    MissingOriginalDestination,
    #[error("unknown DNS upstream '{upstream}'", upstream = .upstream.as_str())]
    UnknownUpstream { upstream: UpstreamTag },
    #[error("DNS response requery cycle at '{upstream}'", upstream = .upstream.as_str())]
    UpstreamCycle { upstream: UpstreamTag },
    #[error("DNS response requery depth exceeds {max}")]
    DepthExceeded { max: usize },
    #[error("DNS response traversal is empty")]
    EmptyTraversal,
}

#[cfg(test)]
mod normalization_tests;
#[cfg(test)]
mod tests;
