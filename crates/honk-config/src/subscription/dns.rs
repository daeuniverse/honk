//! The node-endpoint subset of a subscription's Clash DNS configuration.

use std::collections::HashMap;
use std::net::IpAddr;

use serde_yaml::{Mapping, Value};

use crate::diagnostic::{DiagnosticSources, SettingPath};
use crate::dns::DnsUpstream;
use crate::error::{DetailedConfigError, ErrorCategory};
use crate::types::DnsProtocol;

pub const MAX_SERVERS_PER_LIST: usize = 8;
pub const MAX_POLICIES: usize = 512;
pub const MAX_UNIQUE_UPSTREAMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionDns {
    pub nameservers: Vec<DnsUpstream>,
    pub policies: Vec<SubscriptionDnsPolicy>,
    pub default_nameservers: Vec<DnsUpstream>,
    pub ipv6: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionDnsPolicy {
    pub pattern: String,
    pub upstreams: Vec<DnsUpstream>,
}

impl SubscriptionDns {
    /// Compile only the fields that can affect node endpoint lookups.
    pub fn parse(value: &Value) -> Result<Option<Self>, DetailedConfigError> {
        Self::parse_with_base(value, SettingPath::new("subscription").field("dns"))
    }

    /// Compile with a one-based subscription ordinal for assembled configuration validation.
    pub fn parse_indexed(
        ordinal: usize,
        value: &Value,
    ) -> Result<Option<Self>, DetailedConfigError> {
        Self::parse_with_base(
            value,
            SettingPath::new("subscriptions")
                .index(ordinal)
                .field("dns"),
        )
    }

    fn parse_with_base(
        value: &Value,
        base: SettingPath,
    ) -> Result<Option<Self>, DetailedConfigError> {
        if value.is_null() {
            return Ok(None);
        }
        let root = value.as_mapping().ok_or_else(|| invalid(&base, "dns"))?;
        let ipv6 = root
            .get("ipv6")
            .filter(|v| !v.is_null())
            .map(|v| v.as_bool().ok_or_else(|| invalid(&base, "ipv6")))
            .transpose()?;
        if root
            .get("respect-rules")
            .is_some_and(|v| v != &Value::Bool(false) && !v.is_null())
        {
            return Err(unsupported(&base, "respect-rules"));
        }
        let proxy = servers(&base, root, "proxy-server-nameserver")?;
        let proxy_policy = policies(&base, root, "proxy-server-nameserver-policy")?;
        if proxy.is_empty() && !proxy_policy.is_empty() {
            return Err(invalid(&base, "proxy-server-nameserver-policy"));
        }
        let (mut nameservers, mut policies, policy_key) = if proxy.is_empty() {
            for key in ["fallback", "fallback-filter"] {
                if root.get(key).is_some_and(active) {
                    return Err(unsupported(&base, key));
                }
            }
            (
                servers(&base, root, "nameserver")?,
                policies(&base, root, "nameserver-policy")?,
                "nameserver-policy",
            )
        } else {
            (proxy, proxy_policy, "proxy-server-nameserver-policy")
        };
        let mut default_nameservers = servers(&base, root, "default-nameserver")?;
        if root.contains_key("default-nameserver") && default_nameservers.is_empty() {
            return Err(invalid(&base, "default-nameserver"));
        }
        for (index, server) in default_nameservers.iter().enumerate() {
            if !endpoint_host_is_ip(&server.address) {
                return Err(indexed(invalid(&base, "default-nameserver"), index));
            }
        }
        assign_canonical_names(&mut default_nameservers, "bootstrap");
        dedup_servers(&mut default_nameservers);

        canonicalize_branch(&base, policy_key, &mut nameservers, &mut policies)?;
        if nameservers.is_empty() && policies.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            nameservers,
            policies,
            default_nameservers,
            ipv6,
        }))
    }

    /// Unique imported upstreams in canonical registration order.
    pub fn unique_upstreams(&self) -> Vec<DnsUpstream> {
        let mut seen = HashMap::new();
        let mut out = Vec::new();
        for upstream in self
            .nameservers
            .iter()
            .chain(self.policies.iter().flat_map(|policy| &policy.upstreams))
        {
            if seen.insert(upstream.name.as_str(), ()).is_none() {
                out.push(upstream.clone());
            }
        }
        out
    }

    /// Static labels outrank single-label wildcards, then suffix wildcards.
    pub fn select(&self, host: &str) -> Option<&[DnsUpstream]> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.policies
            .iter()
            .filter_map(|policy| {
                match_rank(&policy.pattern, &host).map(|rank| (rank, policy.upstreams.as_slice()))
            })
            .max_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, servers)| servers)
            .or_else(|| (!self.nameservers.is_empty()).then_some(self.nameservers.as_slice()))
    }
}

fn default_port(protocol: DnsProtocol) -> u16 {
    match protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => 53,
        DnsProtocol::Tls | DnsProtocol::Quic => 853,
        DnsProtocol::Https | DnsProtocol::H3 => 443,
    }
}

fn upstream_key(upstream: &DnsUpstream) -> (u8, String, Option<String>) {
    (
        upstream.protocol as u8,
        upstream.address.clone(),
        upstream.tls_server_name.clone(),
    )
}

fn assign_canonical_names(upstreams: &mut [DnsUpstream], prefix: &str) {
    let mut ids: HashMap<(u8, String, Option<String>), String> = HashMap::new();
    for upstream in upstreams {
        let next_id = ids.len();
        let key = upstream_key(upstream);
        let name = ids
            .entry(key)
            .or_insert_with(|| format!("{prefix}-{next_id}"))
            .clone();
        upstream.name = name;
    }
}

fn dedup_servers(upstreams: &mut Vec<DnsUpstream>) {
    let mut seen = HashMap::new();
    upstreams.retain(|upstream| seen.insert(upstream.name.clone(), ()).is_none());
}

fn canonicalize_branch(
    base: &SettingPath,
    policy_key: &'static str,
    nameservers: &mut Vec<DnsUpstream>,
    policies: &mut [SubscriptionDnsPolicy],
) -> Result<(), DetailedConfigError> {
    let mut ids: HashMap<(u8, String, Option<String>), String> = HashMap::new();
    for upstream in nameservers.iter_mut() {
        let next_id = ids.len();
        let key = upstream_key(upstream);
        upstream.name = ids
            .entry(key)
            .or_insert_with(|| format!("imported-{next_id}"))
            .clone();
    }
    dedup_servers(nameservers);
    for (policy_index, policy) in policies.iter_mut().enumerate() {
        for upstream in &mut policy.upstreams {
            let key = upstream_key(upstream);
            if let Some(existing) = ids.get(&key) {
                upstream.name = existing.clone();
                continue;
            }
            if ids.len() >= MAX_UNIQUE_UPSTREAMS {
                return Err(indexed(unsupported(base, policy_key), policy_index));
            }
            let name = format!("imported-{}", ids.len());
            ids.insert(key, name.clone());
            upstream.name = name;
        }
        dedup_servers(&mut policy.upstreams);
    }
    Ok(())
}

fn endpoint_host_is_ip(address: &str) -> bool {
    let authority = address
        .split_once('?')
        .map_or(address, |(head, _)| head)
        .split('/')
        .next()
        .unwrap_or_default();
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else if authority.parse::<IpAddr>().is_ok() {
        authority
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    host.parse::<IpAddr>().is_ok()
}

fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name
            .rsplit('.')
            .next()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn match_rank(pattern: &str, host: &str) -> Option<Vec<u8>> {
    let (prefix, suffix) = if let Some(suffix) = pattern.strip_prefix("+.") {
        ("+", suffix)
    } else if let Some(suffix) = pattern.strip_prefix("*.") {
        ("*", suffix)
    } else if let Some(suffix) = pattern.strip_prefix('.') {
        (".", suffix)
    } else {
        ("", pattern)
    };
    let remaining = host.strip_suffix(suffix)?;
    let matches = match prefix {
        "" => remaining.is_empty(),
        "+" => remaining.is_empty() || remaining.ends_with('.'),
        "." => !remaining.is_empty() && remaining.ends_with('.'),
        "*" => remaining
            .strip_suffix('.')
            .is_some_and(|r| !r.is_empty() && !r.contains('.')),
        _ => false,
    };
    matches.then(|| {
        let mut rank = vec![3; suffix.split('.').count()];
        rank.push(match prefix {
            "" => 3,
            "*" => 2,
            _ => 1,
        });
        rank
    })
}

fn active(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Sequence(v) => !v.is_empty(),
        Value::Mapping(v) => !v.is_empty(),
        Value::Bool(v) => *v,
        _ => true,
    }
}

fn policies(
    base: &SettingPath,
    root: &Mapping,
    key: &'static str,
) -> Result<Vec<SubscriptionDnsPolicy>, DetailedConfigError> {
    let Some(value) = root.get(key).filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let mapping = value.as_mapping().ok_or_else(|| invalid(base, key))?;
    if mapping.len() > MAX_POLICIES {
        return Err(indexed(unsupported(base, key), MAX_POLICIES));
    }
    mapping
        .iter()
        .enumerate()
        .map(|(index, (pattern, value))| {
            let pattern = pattern
                .as_str()
                .map(str::trim)
                .ok_or_else(|| indexed(invalid(base, key), index))?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let suffix = pattern
                .strip_prefix("+.")
                .or_else(|| pattern.strip_prefix("*."))
                .or_else(|| pattern.strip_prefix('.'))
                .unwrap_or(&pattern);
            if !valid_dns_name(suffix) {
                return Err(indexed(unsupported(base, key), index));
            }
            let upstreams = server_value(base, value, key).map_err(|e| indexed(e, index))?;
            if upstreams.is_empty() {
                return Err(indexed(invalid(base, key), index));
            }
            Ok(SubscriptionDnsPolicy { pattern, upstreams })
        })
        .collect()
}

fn servers(
    base: &SettingPath,
    root: &Mapping,
    key: &'static str,
) -> Result<Vec<DnsUpstream>, DetailedConfigError> {
    root.get(key)
        .map_or_else(|| Ok(Vec::new()), |v| server_value(base, v, key))
}

fn server_value(
    base: &SettingPath,
    value: &Value,
    key: &'static str,
) -> Result<Vec<DnsUpstream>, DetailedConfigError> {
    let values = match value {
        Value::Null => return Ok(Vec::new()),
        Value::String(_) => std::slice::from_ref(value),
        Value::Sequence(values) => values,
        _ => return Err(invalid(base, key)),
    };
    if values.len() > MAX_SERVERS_PER_LIST {
        return Err(indexed(unsupported(base, key), MAX_SERVERS_PER_LIST));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let raw = value
                .as_str()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| indexed(invalid(base, key), index))?;
            if raw.eq_ignore_ascii_case("system") {
                return Err(indexed(unsupported(base, key), index));
            }
            let (has_scheme, scheme, address) = match raw.split_once("://") {
                Some((scheme, rest)) => (true, scheme.to_ascii_lowercase(), rest),
                None => (false, "udp".to_owned(), raw),
            };
            if address.is_empty()
                || address
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            {
                return Err(indexed(invalid(base, key), index));
            }
            let protocol = match scheme.as_str() {
                "udp" => DnsProtocol::Udp,
                "tcp" => DnsProtocol::Tcp,
                "tls" => DnsProtocol::Tls,
                "https" => DnsProtocol::Https,
                "h3" | "http3" => DnsProtocol::H3,
                "quic" => DnsProtocol::Quic,
                _ => return Err(indexed(unsupported(base, key), index)),
            };
            let is_http_dns = matches!(protocol, DnsProtocol::Https | DnsProtocol::H3);
            if address.contains('#') {
                return Err(indexed(unsupported(base, key), index));
            }
            let (before_query, query) = match address.split_once('?') {
                Some((head, q)) => (head, Some(q)),
                None => (address, None),
            };
            let (authority, raw_path) = match before_query.split_once('/') {
                Some((auth, p)) => (auth, Some(p)),
                None => (before_query, None),
            };
            if authority.contains('@')
                || (!is_http_dns && (query.is_some() || raw_path.is_some_and(|p| !p.is_empty())))
            {
                return Err(indexed(unsupported(base, key), index));
            }
            let parse_port = |port_str: &str| -> Result<u16, DetailedConfigError> {
                if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(indexed(invalid(base, key), index));
                }
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| indexed(invalid(base, key), index))?;
                if port == 0 {
                    return Err(indexed(invalid(base, key), index));
                }
                Ok(port)
            };
            let (canonical_host, is_ipv6, port) = if let Some(rest) = authority.strip_prefix('[') {
                let Some((inside, after)) = rest.split_once(']') else {
                    return Err(indexed(invalid(base, key), index));
                };
                let ipv6: std::net::Ipv6Addr = inside
                    .parse()
                    .map_err(|_| indexed(invalid(base, key), index))?;
                let port = if after.is_empty() {
                    None
                } else if let Some(port_str) = after.strip_prefix(':') {
                    Some(parse_port(port_str)?)
                } else {
                    return Err(indexed(invalid(base, key), index));
                };
                (ipv6.to_string(), true, port)
            } else if authority.contains(']') {
                return Err(indexed(invalid(base, key), index));
            } else if !has_scheme
                && raw_path.is_none()
                && query.is_none()
                && let Ok(ipv6) = authority.parse::<std::net::Ipv6Addr>()
            {
                (ipv6.to_string(), true, None)
            } else if authority.bytes().filter(|&b| b == b':').count() > 1 {
                return Err(indexed(invalid(base, key), index));
            } else {
                let (host_raw, port) = match authority.split_once(':') {
                    Some((h, port_str)) => {
                        if h.is_empty() {
                            return Err(indexed(invalid(base, key), index));
                        }
                        (h, Some(parse_port(port_str)?))
                    }
                    None => (authority, None),
                };
                if let Ok(ipv4) = host_raw.parse::<std::net::Ipv4Addr>() {
                    (ipv4.to_string(), false, port)
                } else if valid_dns_name(host_raw) {
                    (
                        host_raw
                            .strip_suffix('.')
                            .unwrap_or(host_raw)
                            .to_ascii_lowercase(),
                        false,
                        port,
                    )
                } else {
                    return Err(indexed(invalid(base, key), index));
                }
            };
            let non_default_port = port.filter(|&p| p != default_port(protocol));
            let formatted_authority = match (is_ipv6, non_default_port, is_http_dns) {
                (true, Some(p), _) => format!("[{canonical_host}]:{p}"),
                (true, None, true) => format!("[{canonical_host}]"),
                (true, None, false) => canonical_host,
                (false, Some(p), _) => format!("{canonical_host}:{p}"),
                (false, None, _) => canonical_host,
            };
            let address = if is_http_dns {
                let path = match raw_path {
                    None | Some("") => "/dns-query".to_owned(),
                    Some(p) => format!("/{p}"),
                };
                match query {
                    Some(q) => format!("{formatted_authority}{path}?{q}"),
                    None => format!("{formatted_authority}{path}"),
                }
            } else {
                formatted_authority
            };
            let check_url = if address.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("{scheme}://[{address}]")
            } else {
                format!("{scheme}://{address}")
            };
            url::Url::parse(&check_url).map_err(|_| indexed(invalid(base, key), index))?;
            Ok(DnsUpstream {
                name: format!("{key}-{index}"),
                address,
                protocol,
                tls_server_name: None,
                outbound: Some("direct".into()),
            })
        })
        .collect()
}

fn invalid(base: &SettingPath, key: &'static str) -> DetailedConfigError {
    error(
        base,
        key,
        "invalid-subscription-dns",
        "invalid subscription DNS field",
    )
}

fn unsupported(base: &SettingPath, key: &'static str) -> DetailedConfigError {
    error(
        base,
        key,
        "unsupported-subscription-dns",
        "subscription DNS field uses unsupported node-resolution semantics",
    )
}

fn error(
    base: &SettingPath,
    key: &'static str,
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    let path = if key == "dns" {
        base.clone()
    } else {
        base.clone().field(key)
    };
    DetailedConfigError::new(
        ErrorCategory::Parse,
        code,
        DiagnosticSources::new(None).root(),
        path,
        message,
    )
}

fn indexed(mut error: DetailedConfigError, index: usize) -> DetailedConfigError {
    error.diagnostic.setting = error.diagnostic.setting.clone().index(index + 1);
    error
}
