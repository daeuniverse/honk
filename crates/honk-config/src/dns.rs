use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Host;

use crate::types::DnsProtocol;

/// Transports served by a standalone DNS bind endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsBindTransport {
    Udp,
    Tcp,
    TcpUdp,
}

/// A validated standalone DNS bind endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsBindEndpoint {
    transport: DnsBindTransport,
    host: String,
    port: u16,
}

/// Error returned when `dns.bind` is not a supported bind endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid dns.bind {value:?}: {reason}")]
pub struct DnsBindError {
    value: String,
    reason: &'static str,
}

impl DnsBindError {
    fn new(value: &str, reason: &'static str) -> Self {
        Self {
            value: value.to_string(),
            reason,
        }
    }
}

impl DnsBindEndpoint {
    /// Parse one non-empty `dns.bind` value.
    pub fn parse(value: &str) -> Result<Self, DnsBindError> {
        if value.is_empty() {
            return Err(DnsBindError::new(value, "an endpoint value is required"));
        }

        let Some((scheme, authority)) = value.split_once("://") else {
            let address = value.parse::<SocketAddr>().map_err(|_| {
                DnsBindError::new(value, "a bare endpoint must be a numeric IP socket address")
            })?;
            return Ok(Self {
                transport: DnsBindTransport::Udp,
                host: address.ip().to_string(),
                port: address.port(),
            });
        };

        let transport = if scheme.eq_ignore_ascii_case("udp") {
            DnsBindTransport::Udp
        } else if scheme.eq_ignore_ascii_case("tcp") {
            DnsBindTransport::Tcp
        } else if scheme.eq_ignore_ascii_case("tcp+udp") {
            DnsBindTransport::TcpUdp
        } else {
            return Err(DnsBindError::new(
                value,
                "unsupported scheme (expected udp://, tcp://, or tcp+udp://)",
            ));
        };

        if authority
            .chars()
            .any(|character| matches!(character, '/' | '?' | '#' | '@' | '\\' | '%'))
        {
            return Err(DnsBindError::new(
                value,
                "the endpoint must contain only a host and port",
            ));
        }

        let (host, port) = parse_bind_authority(value, authority)?;
        Ok(Self {
            transport,
            host,
            port,
        })
    }

    pub fn tcp_enabled(&self) -> bool {
        matches!(
            self.transport,
            DnsBindTransport::Tcp | DnsBindTransport::TcpUdp
        )
    }

    pub fn udp_enabled(&self) -> bool {
        matches!(
            self.transport,
            DnsBindTransport::Udp | DnsBindTransport::TcpUdp
        )
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

fn parse_bind_authority(value: &str, authority: &str) -> Result<(String, u16), DnsBindError> {
    let (host, port, bracketed) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| DnsBindError::new(value, "malformed bracketed IPv6 host"))?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| DnsBindError::new(value, "an explicit port is required"))?;
        (host, port, true)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| DnsBindError::new(value, "an explicit port is required"))?;
        if host.contains(':') || host.contains('[') || host.contains(']') {
            return Err(DnsBindError::new(value, "IPv6 hosts must use brackets"));
        }
        (host, port, false)
    };

    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DnsBindError::new(
            value,
            "the port must be an explicit decimal u16",
        ));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| DnsBindError::new(value, "the port must be an explicit decimal u16"))?;

    let host = if bracketed {
        host.parse::<Ipv6Addr>()
            .map(|address| address.to_string())
            .map_err(|_| DnsBindError::new(value, "malformed bracketed IPv6 host"))?
    } else if host.is_empty() {
        String::new()
    } else if let Ok(address) = host.parse::<IpAddr>() {
        address.to_string()
    } else {
        match Host::parse(host) {
            Ok(Host::Domain(domain)) => domain,
            _ => return Err(DnsBindError::new(value, "invalid host")),
        }
    };

    Ok((host, port))
}

pub const DEFAULT_CLIENT_SUBNET_PROBE_TARGET: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// Configured EDNS Client Subnet behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClientSubnet {
    Preset(Ipv4Net),
    Auto { target: Ipv4Addr },
}

impl DnsClientSubnet {
    pub const fn is_auto(self) -> bool {
        matches!(self, Self::Auto { .. })
    }
}

/// Error returned when `dns.client_subnet` is not supported.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "invalid dns.client_subnet {value:?}: expected empty, auto, auto(IPv4), IPv4, or IPv4/prefix"
)]
pub struct DnsClientSubnetError {
    value: String,
}

impl DnsClientSubnetError {
    fn new(value: &str) -> Self {
        Self {
            value: value.to_string(),
        }
    }
}

/// Default source selected by `dns.use_host: true`.
pub const SYSTEM_HOSTS_PATH: &str = "/etc/hosts";

pub(crate) fn push_host_source(sources: &mut Vec<String>, value: &str) {
    let value = value.trim();
    let path = if ["true", "yes", "1", "on"]
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        SYSTEM_HOSTS_PATH
    } else if value.is_empty()
        || ["false", "no", "0", "off"]
            .iter()
            .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        return;
    } else {
        value
    };
    if !sources.iter().any(|source| source == path) {
        sources.push(path.to_owned());
    }
}

fn deserialize_host_sources<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HostSources {
        Enabled(bool),
        One(String),
        Many(Vec<String>),
    }

    let mut sources = Vec::new();
    match HostSources::deserialize(deserializer)? {
        HostSources::Enabled(enabled) => {
            push_host_source(&mut sources, if enabled { "true" } else { "false" });
        }
        HostSources::One(source) => push_host_source(&mut sources, &source),
        HostSources::Many(values) => {
            for source in values {
                push_host_source(&mut sources, &source);
            }
        }
    }
    Ok(sources)
}

/// DNS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Standalone DNS listener endpoint. Empty disables the listener.
    #[serde(default)]
    pub bind: String,
    /// Ordered hosts sources loaded into one generation-pinned snapshot.
    #[serde(
        default,
        rename = "use_host",
        deserialize_with = "deserialize_host_sources"
    )]
    pub hosts: Vec<String>,
    /// EDNS Client Subnet preset or automatic first-public-hop inference.
    #[serde(default)]
    pub client_subnet: String,
    /// Generation-pinned result of automatic inference; never serialized.
    #[serde(skip)]
    pub resolved_client_subnet: Option<Ipv4Net>,
    #[serde(default)]
    pub upstream: Vec<DnsUpstream>,
    #[serde(default)]
    pub routing: DnsRouting,
    /// DNS request strategy
    #[serde(default)]
    pub strategy: DnsStrategy,
    /// Cache settings
    #[serde(default)]
    pub cache: DnsCacheConfig,
    /// Per-domain fixed TTL overrides. Key = domain, value = TTL seconds.
    /// A value of 0 means "never cache".
    #[serde(default)]
    pub fixed_domain_ttl: HashMap<String, u32>,
}

impl DnsConfig {
    /// Return the configured standalone endpoint, or `None` when disabled.
    pub fn bind_endpoint(&self) -> Result<Option<DnsBindEndpoint>, DnsBindError> {
        if self.bind.is_empty() {
            Ok(None)
        } else {
            DnsBindEndpoint::parse(&self.bind).map(Some)
        }
    }

    pub fn client_subnet_mode(&self) -> Result<Option<DnsClientSubnet>, DnsClientSubnetError> {
        let value = self.client_subnet.trim();
        if value.is_empty() {
            return Ok(None);
        }
        if value.eq_ignore_ascii_case("auto") {
            return Ok(Some(DnsClientSubnet::Auto {
                target: DEFAULT_CLIENT_SUBNET_PROBE_TARGET,
            }));
        }
        let lowercase = value.to_ascii_lowercase();
        if lowercase.starts_with("auto(") && lowercase.ends_with(')') {
            let target = value[5..value.len() - 1]
                .trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| DnsClientSubnetError::new(value))?;
            return Ok(Some(DnsClientSubnet::Auto { target }));
        }
        if let Ok(network) = value.parse::<Ipv4Net>() {
            return Ok(Some(DnsClientSubnet::Preset(network.trunc())));
        }
        let address = value
            .parse::<Ipv4Addr>()
            .map_err(|_| DnsClientSubnetError::new(value))?;
        Ok(Some(DnsClientSubnet::Preset(
            Ipv4Net::new(address, 32).expect("IPv4 /32 is valid"),
        )))
    }

    pub fn effective_client_subnet(&self) -> Result<Option<Ipv4Net>, DnsClientSubnetError> {
        Ok(match self.client_subnet_mode()? {
            Some(DnsClientSubnet::Preset(network)) => Some(network),
            Some(DnsClientSubnet::Auto { .. }) => self.resolved_client_subnet,
            None => None,
        })
    }
}

/// A DNS upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsUpstream {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub protocol: DnsProtocol,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// Outbound node/group to route this upstream through (e.g. `proxy`).
    ///
    /// dae syntax: `name: 'https://dns.google/dns-query' -> proxy`
    /// (legacy alias: `... outbound: proxy`). When set, queries go via the
    /// node/group instead of a direct connection.
    #[serde(default)]
    pub outbound: Option<String>,
}

/// DNS routing configuration.
///
/// Supports both the new request/response rules and the legacy flat
/// `rules` + `fallback` format. When `request.rules` is empty (e.g.
/// after serde from old JSON), `DnsRouter::new` converts legacy rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRouting {
    /// New-style request routing rules.
    #[serde(default, skip_serializing_if = "DnsRequestRouting::is_default")]
    pub request: DnsRequestRouting,
    /// New-style response routing rules.
    #[serde(default, skip_serializing_if = "DnsResponseRouting::is_default")]
    pub response: DnsResponseRouting,
    /// LEGACY flat rules for old JSON/tests — converted in `DnsRouter::new`
    /// when `request.rules` is empty.
    #[serde(default)]
    pub rules: Vec<DnsRule>,
    /// Legacy fallback upstream name.
    #[serde(default = "default_fallback")]
    pub fallback: String,
}

fn default_fallback() -> String {
    "upstream".to_string()
}

impl Default for DnsRouting {
    fn default() -> Self {
        Self {
            request: DnsRequestRouting::default(),
            response: DnsResponseRouting::default(),
            rules: vec![],
            fallback: default_fallback(),
        }
    }
}

/// A legacy DNS routing rule (domain → upstream).
///
/// Kept as a type alias for backward compatibility. New code should
/// use [`DnsRequestRouting`] instead.
pub type DnsRule = DnsLegacyRule;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsLegacyRule {
    /// Domain pattern ("suffix:.cn" | "full:x" | "keyword:" | "regex:" | bare full)
    pub domain: String,
    /// Upstream name to route to
    pub upstream: String,
}

/// Request action: what to do with the DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequestAction {
    /// Drop the query — return empty success answer.
    Reject,
    /// Bypass routing, send directly to the connection's original destination.
    AsIs,
    /// Send to the named upstream.
    Upstream(String),
}

impl DnsRequestAction {
    /// Parse from a config token.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "reject" => DnsRequestAction::Reject,
            "asis" => DnsRequestAction::AsIs,
            other => DnsRequestAction::Upstream(other.to_string()),
        }
    }
}

/// Response action: what to do with the DNS response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnsResponseAction {
    /// Accept the response as-is.
    #[default]
    Accept,
    /// Drop the response — return empty success answer (NODATA).
    Reject,
    /// Re-query the specified upstream.
    Upstream(String),
}

impl DnsResponseAction {
    /// Parse from a config token.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "accept" => DnsResponseAction::Accept,
            "reject" => DnsResponseAction::Reject,
            other => DnsResponseAction::Upstream(other.to_string()),
        }
    }
}

/// How to match a domain name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDomainMatcher {
    /// Exact full-domain match.
    Full(String),
    /// Dot-boundary suffix match (e.g. `.cn` matches `baidu.cn` but not `notcn`).
    Suffix(String),
    /// Case-sensitive substring match.
    Keyword(String),
    /// Regex match against the domain.
    Regex(String),
    /// geosite code — expanded at router build time.
    Geosite(String),
}

/// One AND-ed condition. Matchers within the condition are OR-ed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCond {
    /// Match the query name.
    Qname {
        /// Negate this condition.
        not: bool,
        /// Domain matchers (OR-ed within).
        matchers: Vec<DnsDomainMatcher>,
    },
    /// Match the query type.
    Qtype {
        /// Negate this condition.
        not: bool,
        /// QTYPE values (OR-ed within).
        types: Vec<u16>,
    },
    /// Request only: match the client source address.
    Sip {
        /// Negate this condition.
        not: bool,
        /// IP hosts or CIDRs (OR-ed within).
        cidrs: Vec<String>,
    },
    /// Response only: match the upstream that produced the answer.
    Upstream {
        /// Negate this condition.
        not: bool,
        /// Upstream names (OR-ed within).
        names: Vec<String>,
    },
    /// Response only: match answer IPs.
    Ip {
        /// Negate this condition.
        not: bool,
        /// CIDRs to match against.
        cidrs: Vec<String>,
        /// GeoIP codes to expand.
        geoip: Vec<String>,
    },
}

/// A single request routing rule.
///
/// All conditions are AND-ed; first matching rule wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRequestRule {
    /// Conditions that must all be true.
    pub conditions: Vec<DnsCond>,
    /// Action to take when all conditions match.
    pub action: DnsRequestAction,
}

/// A single response routing rule.
///
/// All conditions are AND-ed; first matching rule wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponseRule {
    /// Conditions that must all be true.
    pub conditions: Vec<DnsCond>,
    /// Action to take when all conditions match.
    pub action: DnsResponseAction,
}

/// Request routing: rules + fallback action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRequestRouting {
    /// Ordered list of rules.
    pub rules: Vec<DnsRequestRule>,
    /// Fallback action when no rule matches. Default: `Upstream("default")`.
    pub fallback: DnsRequestAction,
}

impl Default for DnsRequestRouting {
    fn default() -> Self {
        Self {
            rules: vec![],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        }
    }
}

/// Response routing: rules + fallback action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponseRouting {
    /// Ordered list of rules.
    pub rules: Vec<DnsResponseRule>,
    /// Fallback action when no rule matches. Default: `Accept`.
    pub fallback: DnsResponseAction,
}

impl Default for DnsResponseRouting {
    fn default() -> Self {
        Self {
            rules: vec![],
            fallback: DnsResponseAction::Accept,
        }
    }
}

impl DnsRequestRouting {
    fn is_default(&self) -> bool {
        self.rules.is_empty()
            && matches!(&self.fallback, DnsRequestAction::Upstream(name) if name == "default")
    }
}

impl DnsResponseRouting {
    fn is_default(&self) -> bool {
        self.rules.is_empty() && self.fallback == DnsResponseAction::Accept
    }
}

impl Serialize for DnsRequestRouting {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !self.is_default() {
            return Err(<S::Error as serde::ser::Error>::custom(
                "dns.routing.request rules can only be written in dae syntax",
            ));
        }
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for DnsRequestRouting {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if Option::<serde::de::IgnoredAny>::deserialize(deserializer)?.is_none() {
            Ok(Self::default())
        } else {
            Err(<D::Error as serde::de::Error>::custom(
                "dns.routing.request rules are only supported in dae syntax",
            ))
        }
    }
}

impl Serialize for DnsResponseRouting {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !self.is_default() {
            return Err(<S::Error as serde::ser::Error>::custom(
                "dns.routing.response rules can only be written in dae syntax",
            ));
        }
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for DnsResponseRouting {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if Option::<serde::de::IgnoredAny>::deserialize(deserializer)?.is_none() {
            Ok(Self::default())
        } else {
            Err(<D::Error as serde::de::Error>::custom(
                "dns.routing.response rules are only supported in dae syntax",
            ))
        }
    }
}

impl DnsRouting {
    /// Convert legacy rules into request rules.
    pub fn convert_legacy_rules(&self) -> DnsRequestRouting {
        let mut rules = Vec::with_capacity(self.rules.len());
        for legacy in &self.rules {
            let (matcher, _) = parse_legacy_pattern(&legacy.domain);
            rules.push(DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![matcher],
                }],
                action: DnsRequestAction::Upstream(legacy.upstream.clone()),
            });
        }
        DnsRequestRouting {
            rules,
            fallback: DnsRequestAction::Upstream(self.fallback.clone()),
        }
    }
}

/// Parse a legacy rule pattern into a DnsDomainMatcher.
fn parse_legacy_pattern(pattern: &str) -> (DnsDomainMatcher, String) {
    if let Some(suffix) = pattern.strip_prefix("suffix:") {
        (
            DnsDomainMatcher::Suffix(suffix.to_string()),
            pattern.to_string(),
        )
    } else if let Some(keyword) = pattern.strip_prefix("keyword:") {
        (
            DnsDomainMatcher::Keyword(keyword.to_string()),
            pattern.to_string(),
        )
    } else if let Some(full) = pattern.strip_prefix("full:") {
        (
            DnsDomainMatcher::Full(full.to_string()),
            pattern.to_string(),
        )
    } else if let Some(regex_str) = pattern.strip_prefix("regex:") {
        (
            DnsDomainMatcher::Regex(regex_str.to_string()),
            pattern.to_string(),
        )
    } else {
        (
            DnsDomainMatcher::Full(pattern.to_string()),
            pattern.to_string(),
        )
    }
}

/// Parse a QTYPE token (e.g. "a", "AAAA", "https", "65") into a `u16`.
///
/// Returns `None` for unrecognised names.
pub fn parse_qtype_token(s: &str) -> Option<u16> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u16>() {
        return Some(n);
    }

    match s.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "AAAA" => Some(28),
        "CNAME" => Some(5),
        "MX" => Some(15),
        "TXT" => Some(16),
        "NS" => Some(2),
        "PTR" => Some(12),
        "SOA" => Some(6),
        "SRV" => Some(33),
        "HTTPS" => Some(65),
        "SVCB" => Some(64),
        "ANY" | "*" => Some(255),
        _ => None,
    }
}

/// DNS resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    /// Prefer IPv4
    PreferIpv4,
    /// Prefer IPv6
    PreferIpv6,
    /// IPv4 only
    Ipv4Only,
    /// IPv6 only
    Ipv6Only,
    /// Both IPv4 and IPv6
    #[default]
    Both,
}

/// DNS cache configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCacheConfig {
    /// Enable DNS cache
    #[serde(default = "crate::types::default_true")]
    pub enabled: bool,
    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub ttl: u64,
    /// Maximum cache entries
    #[serde(default = "default_cache_size")]
    pub max_size: usize,
}

fn default_cache_ttl() -> u64 {
    600
}

fn default_cache_size() -> usize {
    10000
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: crate::types::default_true(),
            ttl: default_cache_ttl(),
            max_size: default_cache_size(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind: String::new(),
            hosts: Vec::new(),
            client_subnet: String::new(),
            resolved_client_subnet: None,
            upstream: vec![DnsUpstream {
                name: "default".to_string(),
                address: "223.5.5.5:53".to_string(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }],
            routing: DnsRouting::default(),
            strategy: DnsStrategy::Both,
            cache: DnsCacheConfig {
                enabled: true,
                ttl: 600,
                max_size: 10000,
            },
            fixed_domain_ttl: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_bind_endpoint(value: &str, tcp: bool, udp: bool, host: &str, port: u16) {
        let endpoint = DnsBindEndpoint::parse(value).unwrap();
        assert_eq!(endpoint.tcp_enabled(), tcp, "tcp flag for {value}");
        assert_eq!(endpoint.udp_enabled(), udp, "udp flag for {value}");
        assert_eq!(endpoint.host(), host, "host for {value}");
        assert_eq!(endpoint.port(), port, "port for {value}");
    }

    #[test]
    fn dns_bind_supported_forms_select_exact_transports() {
        assert_bind_endpoint("127.0.0.1:53", false, true, "127.0.0.1", 53);
        assert_bind_endpoint("[2001:db8::1]:0", false, true, "2001:db8::1", 0);
        assert_bind_endpoint("uDp://DNS.Example:0053", false, true, "dns.example", 53);
        assert_bind_endpoint("TCP://127.0.0.1:853", true, false, "127.0.0.1", 853);
        assert_bind_endpoint(
            "TcP+UdP://[2001:0DB8:0:0::1]:53",
            true,
            true,
            "2001:db8::1",
            53,
        );
        assert_bind_endpoint("udp://:0", false, true, "", 0);
    }

    #[test]
    fn dns_bind_bare_numeric_is_udp_and_semantically_canonical() {
        let bare_v4 = DnsBindEndpoint::parse("127.0.0.1:53").unwrap();
        let udp_v4 = DnsBindEndpoint::parse("UDP://127.0.0.1:0053").unwrap();
        assert_eq!(bare_v4, udp_v4);
        assert!(bare_v4.udp_enabled());
        assert!(!bare_v4.tcp_enabled());

        let bare_v6 = DnsBindEndpoint::parse("[2001:db8::1]:53").unwrap();
        let udp_v6 = DnsBindEndpoint::parse("udp://[2001:0db8:0:0::1]:53").unwrap();
        assert_eq!(bare_v6, udp_v6);
    }

    #[test]
    fn dns_bind_rejects_undocumented_or_malformed_forms() {
        for value in [
            "",
            "localhost:53",
            "udp://localhost",
            "udp://user@localhost:53",
            "udp://localhost:53/path",
            "udp://localhost:53?option=true",
            "udp://localhost:53#fragment",
            "tls://localhost:853",
            "udp+tcp://localhost:53",
            "tcp+udp+tcp://localhost:53",
            "udp://tcp://localhost:53",
            "udp://[::1:53",
            "udp://::1:53",
            "udp://[::1]53",
            "udp://[::1]:",
            "udp://localhost:http",
            "udp://localhost:+53",
            "udp://localhost:65536",
            "udp://[fe80::1%25lo]:53",
            " udp://localhost:53",
        ] {
            let error = DnsBindEndpoint::parse(value).unwrap_err();
            assert!(
                error.to_string().contains("dns.bind"),
                "error must identify dns.bind for {value:?}: {error}"
            );
        }
    }

    #[test]
    fn dns_bind_is_serde_defaulted_and_empty_disables_it() {
        let default = DnsConfig::default();
        assert!(default.bind.is_empty());
        assert_eq!(default.bind_endpoint().unwrap(), None);

        let missing: DnsConfig = serde_json::from_str("{}").unwrap();
        assert!(missing.bind.is_empty());
        assert_eq!(missing.bind_endpoint().unwrap(), None);

        let configured: DnsConfig =
            serde_json::from_str(r#"{"bind":"tcp+udp://localhost:53"}"#).unwrap();
        let endpoint = configured.bind_endpoint().unwrap().unwrap();
        assert!(endpoint.tcp_enabled());
        assert!(endpoint.udp_enabled());
        assert_eq!(endpoint.host(), "localhost");
        assert_eq!(endpoint.port(), 53);
    }

    #[test]
    fn dns_client_subnet_parses_fixed_and_auto_modes() {
        let mut config = DnsConfig::default();
        assert_eq!(config.client_subnet_mode().unwrap(), None);

        config.client_subnet = "203.0.113.9".into();
        assert_eq!(
            config.client_subnet_mode().unwrap(),
            Some(DnsClientSubnet::Preset("203.0.113.9/32".parse().unwrap()))
        );
        config.client_subnet = "198.51.100.9/24".into();
        assert_eq!(
            config.client_subnet_mode().unwrap(),
            Some(DnsClientSubnet::Preset("198.51.100.0/24".parse().unwrap()))
        );
        config.client_subnet = "auto".into();
        assert_eq!(
            config.client_subnet_mode().unwrap(),
            Some(DnsClientSubnet::Auto {
                target: DEFAULT_CLIENT_SUBNET_PROBE_TARGET
            })
        );
        config.client_subnet = "auto(9.9.9.9)".into();
        assert_eq!(
            config.client_subnet_mode().unwrap(),
            Some(DnsClientSubnet::Auto {
                target: Ipv4Addr::new(9, 9, 9, 9)
            })
        );
    }

    #[test]
    fn dns_client_subnet_rejects_ambiguous_values() {
        let mut config = DnsConfig::default();
        for value in ["auto()", "auto(dns.google)", "2001:db8::1", "192.0.2.1/33"] {
            config.client_subnet = value.into();
            assert!(config.client_subnet_mode().is_err(), "accepted {value}");
        }
    }

    #[test]
    fn resolved_client_subnet_is_runtime_only() {
        let config = DnsConfig {
            client_subnet: "auto".into(),
            resolved_client_subnet: Some("198.51.100.0/24".parse().unwrap()),
            ..Default::default()
        };

        let serialized = serde_json::to_value(&config).unwrap();
        assert!(serialized.get("resolved_client_subnet").is_none());
        let restored: DnsConfig = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored.resolved_client_subnet, None);
        assert_eq!(restored.client_subnet, "auto");
    }

    #[test]
    fn hosts_sources_are_serde_defaulted_and_accept_legacy_true() {
        assert!(DnsConfig::default().hosts.is_empty());

        let enabled = serde_json::from_str::<DnsConfig>(r#"{"use_host":true}"#).unwrap();
        assert_eq!(enabled.hosts, [SYSTEM_HOSTS_PATH]);

        let sources = serde_json::from_str::<DnsConfig>(
            r#"{"use_host":["/etc/hosts","rules.txt","rules.txt"]}"#,
        )
        .unwrap();
        assert_eq!(sources.hosts, ["/etc/hosts", "rules.txt"]);
    }

    /// Regression: a `[dns]` section without `cache` must still get the
    /// documented defaults (max_size=10000). The derived `Default` used to
    /// produce max_size=0 which broke cache construction at runtime.
    #[test]
    fn missing_cache_section_uses_nonzero_defaults() {
        let cfg: DnsConfig = serde_json::from_str(
            r#"{"upstream":[{"name":"a","address":"223.5.5.5:53","protocol":"udp"}]}"#,
        )
        .unwrap();
        assert_eq!(cfg.cache.max_size, 10000);
        assert_eq!(cfg.cache.ttl, 600);
        assert!(cfg.cache.enabled);
    }

    #[test]
    fn test_default_dns_config_works() {
        let cfg = DnsConfig::default();
        assert_eq!(cfg.upstream.len(), 1);
        assert_eq!(cfg.routing.fallback, "upstream");
        assert!(cfg.routing.request.rules.is_empty());
        assert!(cfg.routing.response.rules.is_empty());
        assert!(matches!(cfg.strategy, DnsStrategy::Both));
    }

    #[test]
    fn missing_strategy_uses_both_for_serde_configs() {
        let cfg: DnsConfig = serde_json::from_str(
            r#"{"upstream":[{"name":"a","address":"223.5.5.5:53","protocol":"udp"}]}"#,
        )
        .unwrap();
        assert!(matches!(cfg.strategy, DnsStrategy::Both));
    }

    #[test]
    fn test_parse_qtype_token() {
        assert_eq!(parse_qtype_token("A"), Some(1));
        assert_eq!(parse_qtype_token("aaaa"), Some(28));
        assert_eq!(parse_qtype_token("HTTPS"), Some(65));
        assert_eq!(parse_qtype_token("svcb"), Some(64));
        assert_eq!(parse_qtype_token("65"), Some(65));
        assert_eq!(parse_qtype_token("999"), Some(999));
        assert_eq!(parse_qtype_token("unknown"), None);
    }

    #[test]
    fn test_dns_request_action_parse() {
        assert_eq!(DnsRequestAction::parse("reject"), DnsRequestAction::Reject);
        assert_eq!(DnsRequestAction::parse("asis"), DnsRequestAction::AsIs);
        assert_eq!(
            DnsRequestAction::parse("alidns"),
            DnsRequestAction::Upstream("alidns".to_string())
        );
    }

    #[test]
    fn test_dns_response_action_parse() {
        assert_eq!(
            DnsResponseAction::parse("accept"),
            DnsResponseAction::Accept
        );
        assert_eq!(
            DnsResponseAction::parse("reject"),
            DnsResponseAction::Reject
        );
        assert_eq!(
            DnsResponseAction::parse("alidns"),
            DnsResponseAction::Upstream("alidns".to_string())
        );
    }

    #[test]
    fn test_legacy_rules_serde_backcompat() {
        let json =
            r#"{"rules":[{"domain":"suffix:.cn","upstream":"alidns"}],"fallback":"default"}"#;
        let routing: DnsRouting = serde_json::from_str(json).unwrap();
        assert_eq!(routing.rules.len(), 1);
        assert_eq!(routing.rules[0].domain, "suffix:.cn");
        assert_eq!(routing.rules[0].upstream, "alidns");
        assert_eq!(routing.fallback, "default");
        // New request rules should be empty (legacy only)
        assert!(routing.request.rules.is_empty());
    }

    #[test]
    fn test_legacy_conversion() {
        let routing = DnsRouting {
            rules: vec![
                DnsLegacyRule {
                    domain: "suffix:.cn".into(),
                    upstream: "alidns".into(),
                },
                DnsLegacyRule {
                    domain: "full:google.com".into(),
                    upstream: "googledns".into(),
                },
            ],
            fallback: "default".into(),
            ..Default::default()
        };
        let converted = routing.convert_legacy_rules();
        assert_eq!(converted.rules.len(), 2);
        assert_eq!(
            converted.fallback,
            DnsRequestAction::Upstream("default".to_string())
        );
    }

    #[test]
    fn legacy_conversion_preserves_rule_order_and_matcher_kind() {
        let routing = DnsRouting {
            rules: vec![
                DnsLegacyRule {
                    domain: "suffix:.cn".into(),
                    upstream: "cn".into(),
                },
                DnsLegacyRule {
                    domain: "keyword:ads".into(),
                    upstream: "block".into(),
                },
                DnsLegacyRule {
                    domain: "full:example.com".into(),
                    upstream: "exact".into(),
                },
                DnsLegacyRule {
                    domain: "regex:^api\\\\.".into(),
                    upstream: "regex".into(),
                },
                DnsLegacyRule {
                    domain: "bare.example".into(),
                    upstream: "bare".into(),
                },
            ],
            ..Default::default()
        };

        let converted = routing.convert_legacy_rules();
        let actions = converted
            .rules
            .iter()
            .map(|rule| &rule.action)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                &DnsRequestAction::Upstream("cn".into()),
                &DnsRequestAction::Upstream("block".into()),
                &DnsRequestAction::Upstream("exact".into()),
                &DnsRequestAction::Upstream("regex".into()),
                &DnsRequestAction::Upstream("bare".into()),
            ]
        );

        fn matcher_kind(rule: &DnsRequestRule) -> &DnsDomainMatcher {
            match &rule.conditions[0] {
                DnsCond::Qname { matchers, .. } => &matchers[0],
                _ => panic!("legacy conversion must produce qname conditions"),
            }
        }
        assert!(matches!(
            matcher_kind(&converted.rules[0]),
            DnsDomainMatcher::Suffix(value) if value == ".cn"
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[1]),
            DnsDomainMatcher::Keyword(value) if value == "ads"
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[2]),
            DnsDomainMatcher::Full(value) if value == "example.com"
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[3]),
            DnsDomainMatcher::Regex(value) if value == "^api\\\\."
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[4]),
            DnsDomainMatcher::Full(value) if value == "bare.example"
        ));
    }

    #[test]
    fn zero_cache_size_remains_accepted_for_runtime_clamping() {
        let cfg: DnsConfig =
            serde_json::from_str(r#"{"cache":{"enabled":true,"ttl":0,"max_size":0}}"#).unwrap();
        assert_eq!(cfg.cache.max_size, 0);
        assert_eq!(cfg.cache.ttl, 0);
    }

    #[test]
    fn test_fixed_domain_ttl_serde() {
        let json = r#"{"upstream":[{"name":"a","address":"223.5.5.5:53","protocol":"udp"}],"fixed_domain_ttl":{"a.test":0,"b.test":300}}"#;
        let cfg: DnsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.fixed_domain_ttl.get("a.test"), Some(&0u32));
        assert_eq!(cfg.fixed_domain_ttl.get("b.test"), Some(&300u32));
    }
}
