use super::{
    DnsCond, DnsConfig, DnsRequestAction, DnsResponseAction, DnsTagMatcher, RequestSource,
};
use crate::diagnostic::{SettingPath, SourceRef};
use crate::error::{DetailedConfigError, ErrorCategory};

impl DnsConfig {
    fn check_upstream_reference(
        &self,
        target: &str,
        source: &SourceRef,
        index: Option<usize>,
        setting: impl FnOnce() -> SettingPath,
    ) -> Result<(), DetailedConfigError> {
        if self.upstream.iter().any(|upstream| upstream.name == target) {
            return Ok(());
        }
        let mut error = DetailedConfigError::new(
            ErrorCategory::Validation,
            "unknown-dns-upstream",
            source.clone(),
            setting(),
            "DNS routing references an undeclared upstream",
        );
        error.diagnostic.entry_index = index.map(|index| index + 1);
        Err(error)
    }

    pub(crate) fn validate_upstream_references_detailed(
        &self,
        source: &SourceRef,
    ) -> Result<(), DetailedConfigError> {
        let routing = &self.routing;
        match routing.request_source() {
            RequestSource::Current => {
                for (index, rule) in routing.request.rules.iter().enumerate() {
                    if let DnsRequestAction::Upstream(target) = &rule.action {
                        self.check_upstream_reference(target, source, Some(index), || {
                            SettingPath::new("dns")
                                .field("routing")
                                .field("request")
                                .field("rules")
                                .index(index + 1)
                                .field("action")
                        })?;
                    }
                }
                if let DnsRequestAction::Upstream(target) = &routing.request.fallback {
                    self.check_upstream_reference(target, source, None, || {
                        SettingPath::new("dns")
                            .field("routing")
                            .field("request")
                            .field("fallback")
                    })?;
                }
            }
            RequestSource::Legacy => {
                for (index, rule) in routing.rules.iter().enumerate() {
                    self.check_upstream_reference(&rule.upstream, source, Some(index), || {
                        SettingPath::new("dns")
                            .field("routing")
                            .field("rules")
                            .index(index + 1)
                            .field("upstream")
                    })?;
                }
                self.check_upstream_reference(&routing.fallback, source, None, || {
                    SettingPath::new("dns").field("routing").field("fallback")
                })
                .map_err(|mut error| {
                    let (code, message) = match routing.fallback.as_str() {
                        "" => (
                            "empty-dns-fallback",
                            "empty legacy DNS fallback has no matching upstream declaration",
                        ),
                        "upstream" => (
                            "missing-dns-fallback",
                            "legacy default fallback 'upstream' requires an upstream declaration",
                        ),
                        _ => return error,
                    };
                    error.diagnostic.code = code;
                    error.diagnostic.message = message;
                    error
                })?;
            }
        }
        for (index, rule) in routing.response.rules.iter().enumerate() {
            if let DnsResponseAction::Upstream(target) = &rule.action {
                self.check_upstream_reference(target, source, Some(index), || {
                    SettingPath::new("dns")
                        .field("routing")
                        .field("response")
                        .field("rules")
                        .index(index + 1)
                        .field("action")
                })?;
            }
        }
        if let DnsResponseAction::Upstream(target) = &routing.response.fallback {
            self.check_upstream_reference(target, source, None, || {
                SettingPath::new("dns")
                    .field("routing")
                    .field("response")
                    .field("fallback")
            })?;
        }
        Ok(())
    }

    /// A `subtag()` rule resolves node server hosts on the dial path, so its
    /// upstream must be pinned `-> direct`: an unpinned upstream follows
    /// traffic routing, which may pick a node whose dial needs this lookup.
    pub(crate) fn validate_node_host_rules_detailed(
        &self,
        source: &SourceRef,
    ) -> Result<(), DetailedConfigError> {
        for (index, rule) in self.routing.request.rules.iter().enumerate() {
            if !rule
                .conditions
                .iter()
                .any(|condition| matches!(condition, DnsCond::Subtag { .. }))
            {
                continue;
            }
            let rejection = if rule.conditions.iter().any(|condition| match condition {
                DnsCond::Qname { .. } => false,
                // Built without the parser, an empty tag list, keyword or regex would claim every tag.
                DnsCond::Subtag { tags, .. } => {
                    tags.is_empty()
                        || tags.iter().any(|tag| match tag {
                            DnsTagMatcher::Exact(value)
                            | DnsTagMatcher::Keyword(value)
                            | DnsTagMatcher::Regex(value) => value.is_empty(),
                        })
                }
                _ => true,
            }) {
                Some((
                    "subtag-dns-condition",
                    "conditions",
                    "a subtag() DNS rule combines only with qname() and names its tags",
                ))
            } else {
                match &rule.action {
                    // Every declaration counts: the runtime keeps the last one.
                    DnsRequestAction::Upstream(name) => {
                        self.upstream
                            .iter()
                            .any(|upstream| {
                                upstream.name == *name
                                    && !upstream.outbound.as_deref().is_some_and(|outbound| {
                                        outbound.eq_ignore_ascii_case("direct")
                                    })
                            })
                            .then_some((
                                "subtag-dns-upstream-route",
                                "action",
                                "a subtag() DNS rule's upstream must be declared `-> direct`",
                            ))
                    }
                    DnsRequestAction::AsIs | DnsRequestAction::Reject => Some((
                        "subtag-dns-action",
                        "action",
                        "a subtag() DNS rule must select an upstream",
                    )),
                }
            };
            if let Some((code, field, message)) = rejection {
                let mut error = DetailedConfigError::new(
                    ErrorCategory::Validation,
                    code,
                    source.clone(),
                    SettingPath::new("dns")
                        .field("routing")
                        .field("request")
                        .field("rules")
                        .index(index + 1)
                        .field(field),
                    message,
                );
                error.diagnostic.entry_index = Some(index + 1);
                return Err(error);
            }
        }
        Ok(())
    }
}
