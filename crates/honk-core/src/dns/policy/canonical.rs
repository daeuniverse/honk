mod normalize {
    use std::net::IpAddr;

    use super::PolicyError;

    pub(super) fn exact(value: &str, field: &'static str) -> Result<String, PolicyError> {
        if value.is_empty() {
            return Err(PolicyError::EmptyName { field });
        }
        Ok(value.to_string())
    }

    pub(super) fn lowercase(value: &str, field: &'static str) -> Result<String, PolicyError> {
        if value.is_empty() {
            return Err(PolicyError::EmptyName { field });
        }
        Ok(value.to_lowercase())
    }

    pub(super) fn host(value: &str) -> Result<String, PolicyError> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(ip.to_string());
        }
        let normalized = value.trim().trim_end_matches('.').to_lowercase();
        if normalized.is_empty() {
            return Err(PolicyError::EmptyName {
                field: "endpoint host",
            });
        }
        if normalized.contains(':')
            || normalized.chars().any(char::is_whitespace)
            || normalized.split('.').any(str::is_empty)
        {
            return Err(PolicyError::InvalidHost {
                value: value.to_string(),
            });
        }
        Ok(normalized)
    }
}
mod wire {
    use super::PolicyError;

    pub(super) struct Writer(Vec<u8>);

    impl Writer {
        pub(super) fn new() -> Self {
            Self(Vec::new())
        }

        pub(super) fn finish(self) -> Vec<u8> {
            self.0
        }

        pub(super) fn byte(&mut self, value: u8) {
            self.0.push(value);
        }

        pub(super) fn u16(&mut self, value: u16) {
            self.0.extend_from_slice(&value.to_be_bytes());
        }

        pub(super) fn u32(&mut self, value: u32) {
            self.0.extend_from_slice(&value.to_be_bytes());
        }

        pub(super) fn u64(&mut self, value: u64) {
            self.0.extend_from_slice(&value.to_be_bytes());
        }

        pub(super) fn len(&mut self, value: usize) -> Result<(), PolicyError> {
            self.u64(u64::try_from(value).map_err(|_| PolicyError::FieldTooLarge)?);
            Ok(())
        }

        pub(super) fn string(&mut self, value: &str) -> Result<(), PolicyError> {
            self.len(value.len())?;
            self.0.extend_from_slice(value.as_bytes());
            Ok(())
        }

        pub(super) fn optional(&mut self, value: Option<&str>) -> Result<(), PolicyError> {
            match value {
                Some(value) => {
                    self.byte(1);
                    self.string(value)?;
                }
                None => self.byte(0),
            }
            Ok(())
        }
    }
}

use std::collections::BTreeMap;

use honk_config::dns::{
    DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsResponseAction, DnsTagMatcher,
};
use honk_config::types::DnsProtocol;

use self::normalize::{exact, host, lowercase};
use self::wire::Writer;
use super::PolicyError;
use crate::dns::endpoint::DnsEndpoint;
use crate::routing::parse_ip_net_str;

const FORMAT_VERSION: u8 = 2;
const ECS_FORMAT_VERSION: u8 = 3;
// Retention remains fixed; the reply TTL keeps its existing identity slot.
const STALE_RETENTION_SECS: u64 = 3600;

pub(super) fn encode(config: &DnsConfig) -> Result<Vec<u8>, PolicyError> {
    let client_subnet = config
        .effective_client_subnet()
        .map_err(|source| PolicyError::InvalidClientSubnet { source })?;
    let mut writer = Writer::new();
    writer.byte(if client_subnet.is_some() {
        ECS_FORMAT_VERSION
    } else {
        FORMAT_VERSION
    });
    writer.len(config.upstream.len())?;
    for upstream in &config.upstream {
        writer.string(&exact(&upstream.name, "upstream name")?)?;
        writer.byte(protocol(upstream.protocol));
        let endpoint = DnsEndpoint::parse(
            &upstream.address,
            upstream.protocol,
            upstream.tls_server_name.as_deref(),
        )
        .map_err(|source| PolicyError::InvalidEndpoint {
            upstream: upstream.name.clone(),
            source,
        })?;
        writer.string(&host(&endpoint.host)?)?;
        writer.u16(endpoint.port);
        writer.string(&endpoint.path)?;
        writer.string(&host(&endpoint.sni)?)?;
        writer.optional(
            upstream
                .outbound
                .as_deref()
                .map(|value| exact(value, "outbound tag"))
                .transpose()?
                .as_deref(),
        )?;
    }

    let request = config.routing.effective_request();
    writer.len(request.rules.len())?;
    for rule in &request.rules {
        conditions(&mut writer, &rule.conditions)?;
        request_action(&mut writer, &rule.action)?;
    }
    request_action(&mut writer, &request.fallback)?;

    writer.len(config.routing.response.rules.len())?;
    for rule in &config.routing.response.rules {
        conditions(&mut writer, &rule.conditions)?;
        response_action(&mut writer, &rule.action)?;
    }
    response_action(&mut writer, &config.routing.response.fallback)?;
    writer.byte(strategy(config));

    let mut fixed = BTreeMap::new();
    for (domain, ttl) in &config.fixed_domain_ttl {
        fixed.insert(exact(domain, "fixed-TTL domain")?, *ttl);
    }
    writer.len(fixed.len())?;
    for (domain, ttl) in fixed {
        writer.string(&domain)?;
        writer.u32(ttl);
    }

    writer.byte(u8::from(config.cache.enabled));
    writer.u64(config.cache.ttl);
    writer.u64(u64::try_from(config.cache.max_size).map_err(|_| PolicyError::FieldTooLarge)?);
    writer.u64(STALE_RETENTION_SECS);
    writer.u32(config.cache.stale_reply_ttl);
    if let Some(network) = client_subnet {
        writer.byte(network.prefix_len());
        for octet in network.network().octets() {
            writer.byte(octet);
        }
    }
    Ok(writer.finish())
}

fn conditions(writer: &mut Writer, values: &[DnsCond]) -> Result<(), PolicyError> {
    writer.len(values.len())?;
    for condition in values {
        match condition {
            DnsCond::Qname { not, matchers } => {
                writer.byte(0);
                writer.byte(u8::from(*not));
                writer.len(matchers.len())?;
                for matcher in matchers {
                    domain_matcher(writer, matcher)?;
                }
            }
            DnsCond::Qtype { not, types } => {
                writer.byte(1);
                writer.byte(u8::from(*not));
                writer.len(types.len())?;
                for value in types {
                    writer.u16(*value);
                }
            }
            DnsCond::Sip { not, cidrs } => {
                if cidrs.is_empty() {
                    return Err(PolicyError::EmptyName {
                        field: "source IP condition",
                    });
                }
                writer.byte(4);
                writer.byte(u8::from(*not));
                writer.len(cidrs.len())?;
                for value in cidrs {
                    let network =
                        parse_ip_net_str(value).ok_or_else(|| PolicyError::InvalidCidr {
                            value: "<redacted>".into(),
                        })?;
                    writer.string(&network.to_string())?;
                }
            }
            DnsCond::Subtag { not, tags } => {
                writer.byte(5);
                writer.byte(u8::from(*not));
                writer.len(tags.len())?;
                for tag in tags {
                    let (kind, value) = match tag {
                        DnsTagMatcher::Exact(value) => (0, value),
                        DnsTagMatcher::Keyword(value) => (1, value),
                        DnsTagMatcher::Regex(value) => {
                            regex::Regex::new(value).map_err(|source| {
                                PolicyError::InvalidRegex {
                                    value: value.clone(),
                                    source,
                                }
                            })?;
                            (2, value)
                        }
                    };
                    writer.byte(kind);
                    writer.string(value)?;
                }
            }
            DnsCond::Upstream { not, names } => {
                writer.byte(2);
                writer.byte(u8::from(*not));
                writer.len(names.len())?;
                for name in names {
                    writer.string(&exact(name, "condition upstream")?)?;
                }
            }
            DnsCond::Ip { not, cidrs, geoip } => {
                writer.byte(3);
                writer.byte(u8::from(*not));
                writer.len(cidrs.len())?;
                for value in cidrs {
                    let network =
                        parse_ip_net_str(value).ok_or_else(|| PolicyError::InvalidCidr {
                            value: "<redacted>".into(),
                        })?;
                    writer.string(&network.to_string())?;
                }
                writer.len(geoip.len())?;
                for value in geoip {
                    writer.string(&exact(value, "GeoIP code")?)?;
                }
            }
        }
    }
    Ok(())
}

fn domain_matcher(writer: &mut Writer, matcher: &DnsDomainMatcher) -> Result<(), PolicyError> {
    let (kind, value) = match matcher {
        DnsDomainMatcher::Full(value) => (0, lowercase(value, "full domain matcher")?),
        DnsDomainMatcher::Suffix(value) => (
            1,
            lowercase(value.trim_start_matches('.'), "suffix domain matcher")?,
        ),
        DnsDomainMatcher::Keyword(value) => (2, value.clone()),
        DnsDomainMatcher::Regex(value) => {
            regex::Regex::new(value).map_err(|source| PolicyError::InvalidRegex {
                value: value.clone(),
                source,
            })?;
            (3, value.clone())
        }
        DnsDomainMatcher::Geosite(value) => (4, exact(value, "geosite code")?),
    };
    writer.byte(kind);
    writer.string(&value)
}

fn request_action(writer: &mut Writer, action: &DnsRequestAction) -> Result<(), PolicyError> {
    match action {
        DnsRequestAction::Reject => writer.byte(0),
        DnsRequestAction::AsIs => writer.byte(1),
        DnsRequestAction::Upstream(name) => {
            writer.byte(2);
            writer.string(&exact(name, "request upstream")?)?;
        }
    }
    Ok(())
}

fn response_action(writer: &mut Writer, action: &DnsResponseAction) -> Result<(), PolicyError> {
    match action {
        DnsResponseAction::Accept => writer.byte(0),
        DnsResponseAction::Reject => writer.byte(1),
        DnsResponseAction::Upstream(name) => {
            writer.byte(2);
            writer.string(&exact(name, "response upstream")?)?;
        }
    }
    Ok(())
}

fn strategy(config: &DnsConfig) -> u8 {
    match config.strategy {
        honk_config::dns::DnsStrategy::PreferIpv4 => 0,
        honk_config::dns::DnsStrategy::PreferIpv6 => 1,
        honk_config::dns::DnsStrategy::Ipv4Only => 2,
        honk_config::dns::DnsStrategy::Ipv6Only => 3,
        honk_config::dns::DnsStrategy::Both => 4,
    }
}

fn protocol(value: DnsProtocol) -> u8 {
    match value {
        DnsProtocol::Udp => 0,
        DnsProtocol::Tcp => 1,
        DnsProtocol::Tls => 2,
        DnsProtocol::Https => 3,
        DnsProtocol::H3 => 4,
        DnsProtocol::Quic => 5,
    }
}
