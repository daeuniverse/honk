use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// skb mark bits reserved for datapath classification and pending decisions.
pub const DATAPATH_RESERVED_MARK_MASK: u32 = 0xc000_0000;

/// A routing rule that matches traffic and sends it to an outbound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(default)]
    pub name: String,
    /// Match conditions
    #[serde(flatten)]
    pub condition: RoutingCondition,
    /// Outbound target
    pub outbound: RoutingOutbound,
    /// Priority (lower = higher priority)
    #[serde(default)]
    pub priority: u32,
    /// If true, this is a "must" rule: matching it does NOT produce a final
    /// outbound decision. Instead, the search continues and the must flag is
    /// propagated to the next matching rule's outbound (Go dae compatible).
    #[serde(default)]
    pub must: bool,
    /// fwmark to set on matched connections (0 = no mark).
    #[serde(default)]
    pub mark: u32,
}

/// Conditions for matching traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RoutingCondition {
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub source_ip: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    #[serde(default)]
    pub source_port: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub mac: Vec<String>,
    #[serde(default)]
    pub geo_ip: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ip_version: Vec<String>,
    #[serde(default)]
    pub dscp: Vec<String>,
    /// Negated matchers (dae `!matcher(...)`): a rule matches iff every
    /// positive matcher matches and none of these do.
    #[serde(default)]
    pub not: RoutingNotCondition,
}

/// Negated matcher set of a routing rule, mirroring [`RoutingCondition`]
/// field for field. Kept as a separate struct so existing serde configs
/// without a `not` key keep parsing unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RoutingNotCondition {
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub source_ip: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    #[serde(default)]
    pub source_port: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub mac: Vec<String>,
    #[serde(default)]
    pub geo_ip: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ip_version: Vec<String>,
    #[serde(default)]
    pub dscp: Vec<String>,
}

/// Mutable view over one matcher field set. The dae parser dispatches each
/// `&&` part into either the positive or the negated set through this view.
pub(crate) struct ConditionFields<'a> {
    pub domain: &'a mut Vec<String>,
    pub domain_suffix: &'a mut Vec<String>,
    pub domain_keyword: &'a mut Vec<String>,
    pub domain_regex: &'a mut Vec<String>,
    pub ip: &'a mut Vec<String>,
    pub source_ip: &'a mut Vec<String>,
    pub port: &'a mut Vec<String>,
    pub source_port: &'a mut Vec<String>,
    pub protocol: &'a mut Vec<String>,
    pub process_name: &'a mut Vec<String>,
    pub mac: &'a mut Vec<String>,
    pub geo_ip: &'a mut Vec<String>,
    pub geosite: &'a mut Vec<String>,
    pub ip_version: &'a mut Vec<String>,
    pub dscp: &'a mut Vec<String>,
}

macro_rules! fields_mut {
    ($self:ident) => {
        ConditionFields {
            domain: &mut $self.domain,
            domain_suffix: &mut $self.domain_suffix,
            domain_keyword: &mut $self.domain_keyword,
            domain_regex: &mut $self.domain_regex,
            ip: &mut $self.ip,
            source_ip: &mut $self.source_ip,
            port: &mut $self.port,
            source_port: &mut $self.source_port,
            protocol: &mut $self.protocol,
            process_name: &mut $self.process_name,
            mac: &mut $self.mac,
            geo_ip: &mut $self.geo_ip,
            geosite: &mut $self.geosite,
            ip_version: &mut $self.ip_version,
            dscp: &mut $self.dscp,
        }
    };
}

impl RoutingCondition {
    pub(crate) fn fields_mut(&mut self) -> ConditionFields<'_> {
        fields_mut!(self)
    }
}

impl RoutingNotCondition {
    pub(crate) fn fields_mut(&mut self) -> ConditionFields<'_> {
        fields_mut!(self)
    }
}

impl RoutingCondition {
    fn matchers(&self) -> impl Iterator<Item = (&'static str, &[String])> {
        [
            ("domain", self.domain.as_slice()),
            ("suffix", self.domain_suffix.as_slice()),
            ("keyword", self.domain_keyword.as_slice()),
            ("regex", self.domain_regex.as_slice()),
            ("geosite", self.geosite.as_slice()),
            ("dip", self.ip.as_slice()),
            ("geoip", self.geo_ip.as_slice()),
            ("src_ip", self.source_ip.as_slice()),
            ("dport", self.port.as_slice()),
            ("sport", self.source_port.as_slice()),
            ("protocol", self.protocol.as_slice()),
            ("process", self.process_name.as_slice()),
            ("smac", self.mac.as_slice()),
            ("ip_version", self.ip_version.as_slice()),
            ("dscp", self.dscp.as_slice()),
        ]
        .into_iter()
        .filter(|(_, values)| !values.is_empty())
    }

    /// Clash-style `(rule, rulePayload)` pair for connection metadata.
    pub fn clash_rule_parts(&self) -> Option<(&'static str, String)> {
        self.matchers()
            .next()
            .map(|(kind, values)| (kind, values.join(",")))
    }

    pub(crate) fn needs_complex_display(&self) -> bool {
        !self.not.is_empty() || self.matchers().nth(1).is_some()
    }
}

impl RoutingNotCondition {
    fn is_empty(&self) -> bool {
        [
            self.domain.as_slice(),
            self.domain_suffix.as_slice(),
            self.domain_keyword.as_slice(),
            self.domain_regex.as_slice(),
            self.ip.as_slice(),
            self.source_ip.as_slice(),
            self.port.as_slice(),
            self.source_port.as_slice(),
            self.protocol.as_slice(),
            self.process_name.as_slice(),
            self.mac.as_slice(),
            self.geo_ip.as_slice(),
            self.geosite.as_slice(),
            self.ip_version.as_slice(),
            self.dscp.as_slice(),
        ]
        .into_iter()
        .all(|values| values.is_empty())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClashRuleDisplay<'a> {
    Simple {
        rule_type: &'static str,
        payload: String,
    },
    Complex {
        payload: &'a str,
    },
    Match,
}

impl ClashRuleDisplay<'_> {
    pub fn rule_type(&self) -> &'static str {
        match self {
            Self::Simple { rule_type, .. } => rule_type,
            Self::Complex { .. } => "complex",
            Self::Match => "match",
        }
    }

    pub fn payload(&self) -> &str {
        match self {
            Self::Simple { payload, .. } => payload,
            Self::Complex { payload } => payload,
            Self::Match => "",
        }
    }
}

fn clash_api_rule_type(kind: &'static str) -> &'static str {
    match kind {
        "suffix" => "domain-suffix",
        "keyword" => "domain-keyword",
        "regex" => "domain-regex",
        "dip" => "ip-cidr",
        "src_ip" => "src-ip-cidr",
        "dport" => "dst-port",
        "sport" => "src-port",
        "process" => "process-name",
        "smac" => "src-mac",
        "ip_version" => "ip-version",
        other => other,
    }
}

/// A routing target. Dae and supported structured formats use one node or
/// group tag; partially wired chain/balancer variants were removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RoutingOutbound {
    Simple(String),
}

impl RoutingOutbound {
    pub fn as_str(&self) -> &str {
        let Self::Simple(name) = self;
        name
    }
}

/// Routing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Routing rules
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    /// Default outbound when no rules match
    #[serde(default = "default_outbound")]
    pub default_outbound: String,
    #[serde(skip)]
    complex_rule_sources: HashMap<String, String>,
}

fn default_outbound() -> String {
    "direct".to_string()
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            rules: vec![],
            default_outbound: "direct".to_string(),
            complex_rule_sources: HashMap::new(),
        }
    }
}

impl RoutingConfig {
    pub(crate) fn record_complex_rule_source(&mut self, name: String, source: String) {
        self.complex_rule_sources.insert(name, source);
    }

    pub fn clash_rule_display<'a>(&'a self, rule: &'a RoutingRule) -> ClashRuleDisplay<'a> {
        self.complex_rule_sources
            .get(&rule.name)
            .map(|source| ClashRuleDisplay::Complex {
                payload: source.as_str(),
            })
            .or_else(|| {
                rule.condition
                    .clash_rule_parts()
                    .map(|(kind, payload)| ClashRuleDisplay::Simple {
                        rule_type: clash_api_rule_type(kind),
                        payload,
                    })
            })
            .unwrap_or(ClashRuleDisplay::Match)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clash_rule_parts_picks_first_condition_kind() {
        let cond = RoutingCondition {
            geosite: vec!["category-dev".into()],
            ..Default::default()
        };
        assert_eq!(
            cond.clash_rule_parts(),
            Some(("geosite", "category-dev".to_string()))
        );

        let cond = RoutingCondition {
            ip: vec!["1.0.0.0/8".into()],
            geo_ip: vec!["telegram".into()],
            ..Default::default()
        };
        assert_eq!(
            cond.clash_rule_parts(),
            Some(("dip", "1.0.0.0/8".to_string()))
        );

        let cond = RoutingCondition {
            port: vec!["22".into(), "80".into(), "443".into()],
            ..Default::default()
        };
        assert_eq!(
            cond.clash_rule_parts(),
            Some(("dport", "22,80,443".to_string()))
        );

        assert_eq!(RoutingCondition::default().clash_rule_parts(), None);
    }

    #[test]
    fn structured_complex_outbound_is_rejected() {
        let encoded = r#"{"type":"or","outbounds":["direct","proxy"]}"#;
        assert!(serde_json::from_str::<RoutingOutbound>(encoded).is_err());
    }
}
