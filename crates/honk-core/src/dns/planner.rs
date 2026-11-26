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
    current_group: Option<UpstreamTag>,
    visited: BTreeSet<UpstreamTag>,
}

impl ResponseTraversal {
    pub fn start(upstream: UpstreamTag) -> Self {
        let visited = BTreeSet::from([upstream.clone()]);
        Self {
            path: vec![upstream.clone()],
            current: upstream,
            current_group: None,
            visited,
        }
    }

    pub(crate) fn start_exchange(requested: UpstreamTag, responder: UpstreamTag) -> Self {
        let current_group = (requested != responder).then(|| requested.clone());
        let mut visited = BTreeSet::from([responder.clone()]);
        visited.insert(requested);
        Self {
            path: vec![responder.clone()],
            current: responder,
            current_group,
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

    pub(crate) fn current_group(&self) -> Option<&UpstreamTag> {
        self.current_group.as_ref()
    }

    pub(crate) fn has_visited(&self, upstream: &UpstreamTag) -> bool {
        self.visited.contains(upstream)
    }

    pub fn path(&self) -> &[UpstreamTag] {
        &self.path
    }

    pub fn advance(self, upstream: UpstreamTag) -> Result<Self, PlanError> {
        self.advance_with_groups(&std::collections::HashMap::new(), upstream)
    }

    pub(crate) fn advance_with_groups(
        mut self,
        groups: &std::collections::HashMap<UpstreamTag, Arc<[UpstreamTag]>>,
        upstream: UpstreamTag,
    ) -> Result<Self, PlanError> {
        if self.visited.contains(&upstream) {
            return Err(PlanError::UpstreamCycle { upstream });
        }
        if let Some(members) = groups.get(&upstream)
            && members.iter().all(|member| self.visited.contains(member))
        {
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
        self.current_group = None;
        Ok(self)
    }

    pub(crate) fn record_responder(&mut self, requested: &UpstreamTag, responder: UpstreamTag) {
        if responder != *requested {
            if let Some(last) = self.path.last_mut() {
                *last = responder.clone();
            }
            self.visited.insert(responder.clone());
            self.current_group = Some(requested.clone());
            self.current = responder;
        }
    }
}

pub struct Planner {
    router: Arc<DnsRouter>,
    upstreams: BTreeSet<UpstreamTag>,
    upstream_groups: Arc<std::collections::HashMap<UpstreamTag, Arc<[UpstreamTag]>>>,
}

impl Planner {
    pub fn new(router: impl Into<Arc<DnsRouter>>, upstreams: BTreeSet<UpstreamTag>) -> Self {
        Self::with_groups(router, upstreams, Arc::default())
    }

    pub(crate) fn with_groups(
        router: impl Into<Arc<DnsRouter>>,
        upstreams: BTreeSet<UpstreamTag>,
        upstream_groups: Arc<std::collections::HashMap<UpstreamTag, Arc<[UpstreamTag]>>>,
    ) -> Self {
        Self {
            router: router.into(),
            upstreams,
            upstream_groups,
        }
    }

    pub fn plan_request(&self, context: RequestContext<'_>) -> Result<RequestPlan, PlanError> {
        self.plan_request_with_source(context, None, None)
            .map(|(plan, _)| plan)
    }

    pub(crate) fn plan_request_with_source(
        &self,
        context: RequestContext<'_>,
        forced: Option<&UpstreamTag>,
        evidence: Option<&mut crate::dns::outcome::RouteSource>,
    ) -> Result<(RequestPlan, crate::dns::outcome::RouteSource), PlanError> {
        if let Some(upstream) = forced {
            if let Some(evidence) = evidence {
                *evidence = crate::dns::outcome::RouteSource::Forced;
            }
            return Ok((
                RequestPlan::Exchange(RequestScope::Upstream(upstream.clone())),
                crate::dns::outcome::RouteSource::Forced,
            ));
        }
        let (decision, source) = self.router.select_request_with_source(
            context.domain,
            context.qtype,
            context.metadata.source_ip(),
        );
        if let Some(evidence) = evidence {
            *evidence = source;
        }
        let plan = match decision {
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
        }?;
        Ok((plan, source))
    }

    pub fn plan_response(
        &self,
        context: ResponseContext<'_>,
        traversal: ResponseTraversal,
    ) -> Result<ResponsePlan, PlanError> {
        match self.router.select_response_with_group(
            context.domain,
            context.qtype,
            context.answer_ips,
            traversal.current().as_str(),
            traversal.current_group().map(UpstreamTag::as_str),
        ) {
            DnsResponseDecision::Accept => Ok(ResponsePlan::Accept),
            DnsResponseDecision::Reject => Ok(ResponsePlan::Reject),
            DnsResponseDecision::Requery(name) => {
                let upstream = UpstreamTag::new(&name)?;
                self.require_known(&upstream)?;
                let traversal =
                    traversal.advance_with_groups(&self.upstream_groups, upstream.clone())?;
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
mod tests;
