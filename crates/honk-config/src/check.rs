use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCheckTarget<'a> {
    Literal(SocketAddr),
    Domain { host: &'a str, port: u16 },
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid check target")]
pub struct InvalidCheckTarget;

/// Decode a DNS target without resolving names. Omitted ports are always 53.
pub fn decode_dns_check_target(value: &str) -> Result<DnsCheckTarget<'_>, InvalidCheckTarget> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return (address.port() != 0)
            .then_some(DnsCheckTarget::Literal(address))
            .ok_or(InvalidCheckTarget);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(DnsCheckTarget::Literal(SocketAddr::new(ip, 53)));
    }
    if let Some(body) = value.strip_prefix('[') {
        let (host, suffix) = body.split_once(']').ok_or(InvalidCheckTarget)?;
        let ip = host.parse::<Ipv6Addr>().map_err(|_| InvalidCheckTarget)?;
        let port = if suffix.is_empty() {
            53
        } else {
            dns_port(suffix.strip_prefix(':').ok_or(InvalidCheckTarget)?)?
        };
        return Ok(DnsCheckTarget::Literal(SocketAddr::new(ip.into(), port)));
    }
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, dns_port(port)?),
        None => (value, 53),
    };
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || "[]:/?#@\\".contains(c))
    {
        return Err(InvalidCheckTarget);
    }
    Ok(DnsCheckTarget::Domain { host, port })
}

fn dns_port(value: &str) -> Result<u16, InvalidCheckTarget> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InvalidCheckTarget);
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(InvalidCheckTarget)
}

/// Prefer the first literal, otherwise the first domain, without DNS I/O.
pub fn select_dns_check_target(
    values: &[String],
) -> Result<Option<DnsCheckTarget<'_>>, InvalidCheckTarget> {
    let mut first_domain = None;
    for value in values.iter().filter(|value| !value.trim().is_empty()) {
        match decode_dns_check_target(value)? {
            target @ DnsCheckTarget::Literal(_) => return Ok(Some(target)),
            target @ DnsCheckTarget::Domain { .. } => {
                first_domain.get_or_insert(target);
            }
        }
    }
    Ok(first_domain)
}

pub(crate) fn validate_dns_check_targets(
    values: &[String],
) -> Result<(), crate::error::DetailedConfigError> {
    for (index, value) in values.iter().enumerate() {
        if !value.trim().is_empty() && decode_dns_check_target(value).is_err() {
            let ordinal = index + 1;
            let mut error = crate::error::DetailedConfigError::new(
                crate::error::ErrorCategory::Validation,
                "invalid-dns-check-target",
                crate::diagnostic::DiagnosticSources::new(None).root(),
                crate::diagnostic::SettingPath::new("global")
                    .field("udp_check_dns")
                    .index(ordinal),
                "DNS check target requires a host and a valid nonzero port; omitted port is 53",
            );
            error.diagnostic.entry_index = Some(ordinal);
            return Err(error);
        }
    }
    Ok(())
}

/// Parsed HTTP authority and request target. Credentials are never used for authorization.
pub struct HttpCheckTarget {
    url: url::Url,
    request_target: String,
}

impl HttpCheckTarget {
    pub fn host(&self) -> &str {
        self.url
            .host_str()
            .expect("validated HTTP host")
            .trim_start_matches('[')
            .trim_end_matches(']')
    }

    /// Credential-free HTTP authority, including IPv6 brackets and any
    /// non-default port.
    pub fn authority(&self) -> &str {
        &self.url[url::Position::BeforeHost..url::Position::AfterPort]
    }

    pub fn port(&self) -> u16 {
        self.url
            .port_or_known_default()
            .expect("HTTP scheme default")
    }

    pub fn is_https(&self) -> bool {
        self.url.scheme() == "https"
    }

    pub fn request_target(&self) -> &str {
        &self.request_target
    }
}

// URL serialization shortens dot segments; health checks must send the configured bytes.
fn configured_request_target(target: &str) -> String {
    let target = target.split_once('#').map_or(target, |(target, _)| target);
    if target.starts_with('?') {
        format!("/{target}")
    } else if target.is_empty() {
        "/".to_owned()
    } else {
        target.to_owned()
    }
}

pub fn decode_http_check_target(
    value: &str,
    default_https: bool,
) -> Result<HttpCheckTarget, InvalidCheckTarget> {
    let value = value.trim();
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\\'))
    {
        return Err(InvalidCheckTarget);
    }
    let scheme = value
        .split_once("://")
        .filter(|(prefix, _)| !prefix.contains(['/', '?', '#']));
    let authority_and_target = scheme.map_or(value, |(_, rest)| rest);
    let target_start = authority_and_target
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_target.len());
    // Url repairs surplus authority slashes; raw-path preservation cannot
    // accept a different authority boundary without exposing userinfo.
    if target_start == 0 {
        return Err(InvalidCheckTarget);
    }
    let url = if scheme.is_some() {
        url::Url::parse(value)
    } else {
        url::Url::parse(&format!(
            "{}://{value}",
            if default_https { "https" } else { "http" }
        ))
    }
    .map_err(|_| InvalidCheckTarget)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.port() == Some(0)
    {
        return Err(InvalidCheckTarget);
    }
    let request_target = configured_request_target(&authority_and_target[target_start..]);
    Ok(HttpCheckTarget {
        url,
        request_target,
    })
}

/// Health checks retain dae's comma-separated literal fallback list.
pub fn decode_health_http_target(value: &str) -> Result<HttpCheckTarget, InvalidCheckTarget> {
    decode_http_check_target(value.split(',').next().unwrap_or(""), false)
}
