use super::{
    DnsCond, DnsConfig, DnsRequestAction, DnsResponseAction, DnsTagMatcher, MAX_DNS_RACE_UPSTREAMS,
    RequestSource,
};
use crate::diagnostic::{SettingPath, SourceRef};
use crate::error::{DetailedConfigError, ErrorCategory};

impl DnsConfig {
    fn validate_upstream_groups_detailed(
        &self,
        source: &SourceRef,
    ) -> Result<(), DetailedConfigError> {
        let group_error =
            |ordinal: usize, setting: SettingPath, code: &'static str, message: &'static str| {
                let mut error = DetailedConfigError::new(
                    ErrorCategory::Validation,
                    code,
                    source.clone(),
                    setting,
                    message,
                );
                error.diagnostic.entry_index = Some(ordinal);
                error
            };

        for (index, group) in self.upstream_groups.iter().enumerate() {
            let ordinal = index + 1;
            let name_path = || {
                SettingPath::new("dns")
                    .field("upstream_groups")
                    .index(ordinal)
                    .field("name")
            };
            if group.name.is_empty() {
                return Err(group_error(
                    ordinal,
                    name_path(),
                    "invalid-dns-race",
                    "DNS race group name must not be empty",
                ));
            }
            if self
                .upstream
                .iter()
                .any(|upstream| upstream.name == group.name)
            {
                return Err(group_error(
                    ordinal,
                    name_path(),
                    "conflicting-dns-upstream-name",
                    "DNS race group name conflicts with a declared upstream",
                ));
            }
            if self.upstream_groups[..index]
                .iter()
                .any(|prior| prior.name == group.name)
            {
                return Err(group_error(
                    ordinal,
                    name_path(),
                    "conflicting-dns-upstream-name",
                    "duplicate DNS race group name",
                ));
            }
            if !(2..=MAX_DNS_RACE_UPSTREAMS).contains(&group.upstreams.len()) {
                return Err(group_error(
                    ordinal,
                    SettingPath::new("dns")
                        .field("upstream_groups")
                        .index(ordinal)
                        .field("upstreams"),
                    "invalid-dns-race",
                    "DNS race group requires between 2 and 8 upstreams",
                ));
            }
        }

        for (index, group) in self.upstream_groups.iter().enumerate() {
            let ordinal = index + 1;
            for (member_index, member) in group.upstreams.iter().enumerate() {
                let member_path = || {
                    SettingPath::new("dns")
                        .field("upstream_groups")
                        .index(ordinal)
                        .field("upstreams")
                        .index(member_index + 1)
                };
                if member.is_empty() {
                    return Err(group_error(
                        ordinal,
                        member_path(),
                        "invalid-dns-race",
                        "DNS race group member name must not be empty",
                    ));
                }
                if member == &group.name {
                    return Err(group_error(
                        ordinal,
                        member_path(),
                        "invalid-dns-race",
                        "DNS race group cannot reference itself",
                    ));
                }
                if group.upstreams[..member_index]
                    .iter()
                    .any(|prior| prior == member)
                {
                    return Err(group_error(
                        ordinal,
                        member_path(),
                        "invalid-dns-race",
                        "DNS race group cannot list the same upstream twice",
                    ));
                }
                if self
                    .upstream_groups
                    .iter()
                    .any(|other| other.name == *member)
                {
                    return Err(group_error(
                        ordinal,
                        member_path(),
                        "nested-dns-upstream-group",
                        "DNS race group members must be physical upstreams, not another race group",
                    ));
                }
                if !self
                    .upstream
                    .iter()
                    .any(|upstream| upstream.name == *member)
                {
                    return Err(group_error(
                        ordinal,
                        member_path(),
                        "unknown-dns-upstream",
                        "DNS race group references an undeclared upstream",
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_upstream_reference(
        &self,
        target: &str,
        source: &SourceRef,
        index: Option<usize>,
        setting: impl FnOnce() -> SettingPath,
    ) -> Result<(), DetailedConfigError> {
        if self.upstream.iter().any(|upstream| upstream.name == target)
            || self
                .upstream_groups
                .iter()
                .any(|group| group.name == target)
        {
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
        self.validate_upstream_groups_detailed(source)?;
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
                        let non_direct = |target: &str| {
                            self.upstream.iter().any(|upstream| {
                                upstream.name == target
                                    && !upstream.outbound.as_deref().is_some_and(|outbound| {
                                        outbound.eq_ignore_ascii_case("direct")
                                    })
                            })
                        };
                        let rejected = if let Some(group) = self
                            .upstream_groups
                            .iter()
                            .find(|group| group.name == *name)
                        {
                            group.upstreams.iter().any(|member| non_direct(member))
                        } else {
                            non_direct(name)
                        };
                        rejected.then_some((
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
