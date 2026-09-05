use super::{
    Section, extract_fn_args, extract_nested_all, has_routing_fallback, normalize_geosite_code,
    parse_bool, parse_ip_prefer, parse_kv_pair, parse_kv_pairs, split_nested_sections,
    strip_tag_arg,
};
use crate::dns::DnsConfig;

pub(super) fn parse_section(section: &Section) -> Result<DnsConfig, crate::ConfigError> {
    let dns_subs =
        split_nested_sections(&section.body, &["upstream", "routing", "fixed_domain_ttl"])?;
    let mut cfg = DnsConfig::default();
    let mut saw_upstream = false;
    let dns_body = dns_subs.first().map(|s| s.body.as_str()).unwrap_or("");
    let kv = parse_kv_pairs(dns_body);
    if let Some(bind) = kv.get("bind") {
        cfg.bind.clone_from(bind);
        cfg.bind_endpoint()
            .map_err(|error| crate::ConfigError::Parse(error.to_string()))?;
    }
    if kv.contains_key("hosts_file") {
        return Err(crate::ConfigError::Parse(
            "dns.hosts_file was removed; use one or more use_host paths".into(),
        ));
    }
    for (key, source) in dns_body.lines().filter_map(parse_kv_pair) {
        if key == "use_host" {
            crate::dns::push_host_source(&mut cfg.hosts, source);
        }
    }
    if let Some(value) = kv.get("client_subnet") {
        cfg.client_subnet.clone_from(value);
        cfg.client_subnet_mode()
            .map_err(|error| crate::ConfigError::Parse(error.to_string()))?;
    }

    if let Some(v) = kv.get("ipversion_prefer") {
        cfg.strategy = parse_ip_prefer(v);
    }
    if let Some(v) = kv.get("optimistic_cache") {
        cfg.cache.enabled = parse_bool(v);
    }
    if let Some(v) = kv.get("optimistic_cache_ttl") {
        cfg.cache.ttl = v.parse().unwrap_or(60);
    }
    if let Some(v) = kv.get("max_cache_size") {
        cfg.cache.max_size = v.parse().unwrap_or(10000);
    }

    for sub in dns_subs.iter().skip(1) {
        match sub.name.as_str() {
            "upstream" => {
                if !saw_upstream {
                    cfg.upstream.clear();
                    saw_upstream = true;
                }
                cfg.upstream.extend(parse_dns_upstreams(&sub.body));
            }
            "routing" => {
                for req_body in extract_nested_all(&sub.body, "request") {
                    let has_fallback = has_routing_fallback(&req_body);
                    let request = parse_dns_request_routing(&req_body);
                    cfg.routing.request.rules.extend(request.rules);
                    if !has_fallback {
                        continue;
                    }
                    cfg.routing.request.fallback = request.fallback;
                    // Sync legacy fallback for callers that only look there.
                    if let crate::dns::DnsRequestAction::Upstream(ref name) =
                        cfg.routing.request.fallback
                    {
                        cfg.routing.fallback = name.clone();
                    }
                }
                for resp_body in extract_nested_all(&sub.body, "response") {
                    let has_fallback = has_routing_fallback(&resp_body);
                    let response = parse_dns_response_routing(&resp_body);
                    cfg.routing.response.rules.extend(response.rules);
                    if has_fallback {
                        cfg.routing.response.fallback = response.fallback;
                    }
                }
            }
            "fixed_domain_ttl" => {
                cfg.fixed_domain_ttl
                    .extend(parse_fixed_domain_ttl(&sub.body));
            }
            _ => {}
        }
    }

    Ok(cfg)
}

fn parse_dns_upstreams(body: &str) -> Vec<crate::dns::DnsUpstream> {
    let mut upstreams = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(pos) = trimmed.find(':') {
            let name = trimmed[..pos].trim().to_string();
            let rest = trimmed[pos + 1..].trim();
            // Optional via-proxy suffix (same line):
            //   preferred:  name: 'uri' -> proxy
            //   legacy:     name: 'uri' outbound: proxy
            let (uri, outbound) = if let Some((left, right)) = rest.split_once("->") {
                let uri_part = left.trim().trim_matches('\'').trim_matches('"');
                let outbound_part = right.trim().trim_matches('\'').trim_matches('"');
                let outbound = if outbound_part.is_empty() {
                    None
                } else {
                    Some(outbound_part.to_string())
                };
                (uri_part, outbound)
            } else if let Some(opos) = rest.find("outbound:") {
                let uri_part = rest[..opos].trim().trim_matches('\'').trim_matches('"');
                let outbound_part = rest[opos + 9..].trim().trim_matches('\'').trim_matches('"');
                (uri_part, Some(outbound_part.to_string()))
            } else {
                (rest.trim_matches('\'').trim_matches('"'), None)
            };
            let (protocol, address) = parse_upstream_uri(uri);
            let (address, explicit_sni) = extract_tls_server_name(address);
            let tls_server_name = explicit_sni.or_else(|| sni_from_upstream_address(&address));
            upstreams.push(crate::dns::DnsUpstream {
                name,
                address,
                protocol,
                tls_server_name,
                outbound,
            });
        }
    }
    upstreams
}

fn parse_upstream_uri(uri: &str) -> (crate::types::DnsProtocol, String) {
    let uri = uri.trim();
    if let Some(rest) = uri.strip_prefix("tcp+udp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("udp+tcp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("h3://") {
        (crate::types::DnsProtocol::H3, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("http3://") {
        (crate::types::DnsProtocol::H3, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("quic://") {
        (crate::types::DnsProtocol::Quic, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("https://") {
        (crate::types::DnsProtocol::Https, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("tls://") {
        (crate::types::DnsProtocol::Tls, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("tcp://") {
        (crate::types::DnsProtocol::Tcp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("udp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else {
        (crate::types::DnsProtocol::Udp, uri.to_string())
    }
}

/// Derive a TLS SNI hostname from a stripped upstream address.
///
/// Returns `None` when the host is a bare IP (no SNI needed / not useful).
fn sni_from_upstream_address(address: &str) -> Option<String> {
    let hostport = address.split('/').next().unwrap_or(address);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        hostport
            .rsplit_once(':')
            .map(|(h, p)| {
                // Only treat as host:port when the suffix is numeric.
                if p.chars().all(|c| c.is_ascii_digit()) {
                    h
                } else {
                    hostport
                }
            })
            .unwrap_or(hostport)
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    // Bare IPs do not need (and often cannot use) SNI.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(host.to_string())
}

/// Strip an explicit `tls_server_name=` query parameter from an upstream
/// address, e.g. `tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com`.
/// Needed for IP-literal TLS upstreams whose certificate hostname differs
/// from the dial address. Other query pairs are preserved.
fn extract_tls_server_name(address: String) -> (String, Option<String>) {
    let Some(qpos) = address.find('?') else {
        return (address, None);
    };
    let (base, query) = address.split_at(qpos);
    let mut sni = None;
    let mut kept = Vec::new();
    for pair in query[1..].split('&') {
        if let Some(v) = pair.strip_prefix("tls_server_name=") {
            let v = v.trim();
            if !v.is_empty() {
                sni = Some(v.to_string());
            }
        } else if !pair.is_empty() {
            kept.push(pair);
        }
    }
    let address = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    (address, sni)
}

/// Parse `fixed_domain_ttl { domain: N ... }` into a HashMap.
fn parse_fixed_domain_ttl(body: &str) -> std::collections::HashMap<String, u32> {
    let mut map = std::collections::HashMap::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(pos) = trimmed.find(':') {
            let key = trimmed[..pos].trim().trim_matches('"').trim_matches('\'');
            let val = trimmed[pos + 1..].split_whitespace().next().unwrap_or("");
            if let Ok(n) = val.parse::<u32>() {
                map.insert(key.to_string(), n);
            }
        }
    }
    map
}

/// Parse `routing.request { ... }` block.
fn parse_dns_request_routing(body: &str) -> crate::dns::DnsRequestRouting {
    let mut routing = crate::dns::DnsRequestRouting::default();

    for line in body.lines() {
        let mut trimmed = line.trim();
        if let Some(pos) = trimmed.find("//") {
            trimmed = trimmed[..pos].trim();
        } else if let Some(pos) = trimmed.find('#') {
            // Only strip # if preceded by space (to avoid stripping domain # itself)
            if pos > 0 && trimmed.as_bytes()[pos - 1] == b' ' {
                trimmed = trimmed[..pos].trim();
            }
        }
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("fallback:") || trimmed.starts_with("default:") {
            let fb = trimmed.split_once(':').unwrap().1.trim();
            routing.fallback = crate::dns::DnsRequestAction::parse(fb);
            continue;
        }

        if let Some(arrow_pos) = trimmed.find("->") {
            let left = trimmed[..arrow_pos].trim();
            let right = trimmed[arrow_pos + 2..].trim();
            let action = crate::dns::DnsRequestAction::parse(right);
            let conditions = parse_dns_conditions(left, false);
            // Skip rules whose conditions were all ignored (e.g. sub()/node()).
            if !conditions.is_empty() {
                routing
                    .rules
                    .push(crate::dns::DnsRequestRule { conditions, action });
            }
        }
    }

    routing
}

/// Parse `routing.response { ... }` block.
fn parse_dns_response_routing(body: &str) -> crate::dns::DnsResponseRouting {
    let mut routing = crate::dns::DnsResponseRouting::default();

    for line in body.lines() {
        let mut trimmed = line.trim();
        if let Some(pos) = trimmed.find("//") {
            trimmed = trimmed[..pos].trim();
        } else if let Some(pos) = trimmed.find('#')
            && pos > 0
            && trimmed.as_bytes()[pos - 1] == b' '
        {
            trimmed = trimmed[..pos].trim();
        }
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("fallback:") || trimmed.starts_with("default:") {
            let fb = trimmed.split_once(':').unwrap().1.trim();
            routing.fallback = crate::dns::DnsResponseAction::parse(fb);
            continue;
        }

        if let Some(arrow_pos) = trimmed.find("->") {
            let left = trimmed[..arrow_pos].trim();
            let right = trimmed[arrow_pos + 2..].trim();
            let action = crate::dns::DnsResponseAction::parse(right);
            let conditions = parse_dns_conditions(left, true);
            // Skip rules whose conditions were all ignored (e.g. sub()/node()).
            if !conditions.is_empty() {
                routing
                    .rules
                    .push(crate::dns::DnsResponseRule { conditions, action });
            }
        }
    }

    routing
}

/// Parse a chain of `&&`-separated conditions.
fn parse_dns_conditions(expr: &str, is_response: bool) -> Vec<crate::dns::DnsCond> {
    let mut conds = Vec::new();
    let parts: Vec<&str> = expr.split("&&").map(|s| s.trim()).collect();

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (not, inner) = if let Some(rest) = part.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, part)
        };

        if let Some(args) = extract_fn_args(inner, "qname") {
            let matchers = parse_dns_qname_args(&args);
            conds.push(crate::dns::DnsCond::Qname { not, matchers });
            continue;
        }

        if let Some(args) = extract_fn_args(inner, "qtype") {
            let types: Vec<u16> = args
                .iter()
                .filter_map(|a| crate::dns::parse_qtype_token(a))
                .collect();
            conds.push(crate::dns::DnsCond::Qtype { not, types });
            continue;
        }

        if let Some(cidrs) = extract_fn_args(inner, "sip") {
            conds.push(crate::dns::DnsCond::Sip { not, cidrs });
            continue;
        }

        if is_response {
            if let Some(args) = extract_fn_args(inner, "upstream") {
                conds.push(crate::dns::DnsCond::Upstream { not, names: args });
                continue;
            }
            if let Some(args) = extract_fn_args(inner, "ip") {
                let (cidrs, geoip) = parse_dns_ip_args(&args);
                conds.push(crate::dns::DnsCond::Ip { not, cidrs, geoip });
                continue;
            }
        }

        // sub() / node() / subnode() — not supported for client DNS, warn
        if inner.starts_with("sub(") || inner.starts_with("node(") || inner.starts_with("subnode(")
        {
            eprintln!(
                "dns routing: ignoring unsupported function {} (out of scope for client DNS)",
                inner
            );
            continue;
        }

        // unknown condition function — silently ignored
    }

    conds
}

/// Parse qname(args) into a list of domain matchers.
fn parse_dns_qname_args(args: &[String]) -> Vec<crate::dns::DnsDomainMatcher> {
    let mut matchers = Vec::new();
    for a in args {
        let a = a.trim();
        if a.is_empty() {
            continue;
        }
        if let Some(v) = strip_tag_arg(a, "geosite:") {
            matchers.push(crate::dns::DnsDomainMatcher::Geosite(
                normalize_geosite_code(&v),
            ));
        } else if let Some(v) = strip_tag_arg(a, "keyword:") {
            matchers.push(crate::dns::DnsDomainMatcher::Keyword(v));
        } else if let Some(v) = strip_tag_arg(a, "full:") {
            matchers.push(crate::dns::DnsDomainMatcher::Full(v));
        } else if let Some(v) = strip_tag_arg(a, "regex:") {
            matchers.push(crate::dns::DnsDomainMatcher::Regex(v));
        } else if let Some(v) = strip_tag_arg(a, "suffix:") {
            matchers.push(crate::dns::DnsDomainMatcher::Suffix(v));
        } else {
            // Bare argument → suffix (dae compatible)
            matchers.push(crate::dns::DnsDomainMatcher::Suffix(a.to_string()));
        }
    }
    matchers
}

/// Parse ip(...) args into (cidrs, geoip_codes).
fn parse_dns_ip_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut cidrs = Vec::new();
    let mut geoip = Vec::new();
    for a in args {
        let a = a.trim();
        if let Some(v) = strip_tag_arg(a, "geoip:") {
            geoip.push(v.to_lowercase());
        } else {
            cidrs.push(a.to_string());
        }
    }
    (cidrs, geoip)
}
