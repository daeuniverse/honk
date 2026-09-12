use std::collections::HashMap;

use super::cursor::Segment;
use super::lexer::quoted_end;
use super::read::{self, Text};
use super::scalars;
use super::{ParserDiagnostics, lenient, normalize_geosite_code, parse_ip_prefer};
use crate::ConfigDiagnostic;
use crate::diagnostic::{DetailedDiagnostic, SafeValue, SettingPath, Severity};
use crate::dns::DnsConfig;
use crate::error::{DetailedConfigError, ErrorCategory};

fn children<'d, 'a>(
    section: &Segment<'d, 'a>,
    recognized: &[&str],
    lines: &mut Vec<Text<'d, 'a>>,
    blocks: &mut Vec<Segment<'d, 'a>>,
    diagnostics: &mut ParserDiagnostics<'_>,
) {
    if let Some(body) = section.body() {
        for child in body {
            if let Some(header) = read::block_header(&child) {
                if recognized.contains(&header.raw()) {
                    blocks.push(child);
                } else {
                    header.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-block",
                        "unknown nested block ignored",
                    );
                }
            } else {
                lines.push(Text::segment(&child));
            }
        }
    }
}
fn terminal_scalar_quote(
    line: Text<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<(), DetailedConfigError> {
    if !line.has_error() {
        return Ok(());
    }
    let prior = diagnostics.output.iter().rposition(|diagnostic| {
        diagnostic.code == "unterminated-quote"
            && diagnostic.source.same_source(&line.source.reference())
            && diagnostic
                .span
                .as_ref()
                .is_some_and(|span| span.start < line.span.end && line.span.start < span.end)
    });
    let mut diagnostic = prior
        .map(|index| diagnostics.remove(index))
        .unwrap_or_else(|| {
            line.source.diagnostic(
                line.span,
                Severity::Error,
                "unterminated-quote",
                "quote must close on the same physical line",
            )
        });
    diagnostic.terminal = true;
    Err(DetailedConfigError {
        category: ErrorCategory::Parse,
        diagnostic: Box::new(diagnostic),
    })
}

fn dns_error(
    text: Text<'_, '_>,
    code: &'static str,
    field: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    let mut error = DetailedConfigError::new(
        ErrorCategory::Parse,
        code,
        text.source.reference(),
        SettingPath::new("dns").field(field),
        message,
    );
    let (line, column) = text.source.location(text.span.start);
    error.diagnostic.line = Some(line);
    error.diagnostic.span = Some(text.span.start..text.span.end);
    error.diagnostic.byte_column = Some(column);
    error
}

fn raw_fields<'d, 'a>(
    lines: Vec<Text<'d, 'a>>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<(HashMap<&'d str, Text<'d, 'a>>, Vec<Text<'d, 'a>>), DetailedConfigError> {
    let mut raw = HashMap::new();
    let mut hosts = Vec::new();
    for line in lines {
        terminal_scalar_quote(line, diagnostics)?;
        let Some((key, value)) = line.kv() else {
            line.notice(
                diagnostics,
                Severity::Warning,
                "unknown-statement",
                "unknown DNS statement ignored",
            );
            continue;
        };
        if ![
            "bind",
            "hosts_file",
            "use_host",
            "client_subnet",
            "ipversion_prefer",
            "optimistic_cache",
            "optimistic_cache_ttl",
            "optimistic_stale_reply_ttl",
            "max_cache_size",
        ]
        .contains(&key.raw())
        {
            key.notice(
                diagnostics,
                Severity::Warning,
                "unknown-key",
                "unknown scalar key ignored",
            );
            continue;
        }
        let key = key.raw();
        diagnostics.register_field(key, value);
        value.warn_glued_hash(diagnostics);
        if key == "use_host" {
            hosts.push(value);
        }
        raw.insert(key, value);
    }
    Ok((raw, hosts))
}

pub(super) fn parse_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<DnsConfig, super::ParseFailure> {
    let mut lines = Vec::new();
    let mut dns_subs = Vec::new();
    for root in section {
        children(
            root,
            &["upstream", "routing", "fixed_domain_ttl"],
            &mut lines,
            &mut dns_subs,
            diagnostics,
        );
    }
    let (settings, hosts) = raw_fields(lines, diagnostics)?;
    let mut cfg = DnsConfig::default();
    let mut saw_upstream = false;
    if let Some(bind) = settings.get("bind") {
        cfg.bind = bind.unquote().raw().to_owned();
        cfg.bind_endpoint().map_err(|_| {
            dns_error(
                *bind,
                "invalid-config-value",
                "bind",
                "invalid configuration value",
            )
        })?;
    }
    if let Some(hosts_file) = settings.get("hosts_file") {
        return Err(dns_error(
            *hosts_file,
            "removed-dns-hosts-file",
            "hosts_file",
            "hosts_file was removed; use one or more use_host paths",
        )
        .into());
    }
    for value in hosts {
        crate::dns::push_host_source(&mut cfg.hosts, value.unquote().raw());
    }
    if let Some(value) = settings.get("client_subnet") {
        cfg.client_subnet = value.unquote().raw().to_owned();
        cfg.client_subnet_mode().map_err(|_| {
            dns_error(
                *value,
                "invalid-config-value",
                "client_subnet",
                "expected empty, auto, auto(IPv4), IPv4, or IPv4/prefix",
            )
        })?;
    }
    if let Some(v) = settings.get("ipversion_prefer") {
        let value = v.unquote().raw();
        cfg.strategy = lenient(
            parse_ip_prefer(value),
            crate::dns::DnsStrategy::Both,
            diagnostics,
            || {
                ConfigDiagnostic {
                setting: "dns.ipversion_prefer".to_string(),
                value: value.to_string(),
                message: "honk could not parse the preference as decimal 0, 4 or 6; using fallback: no preference"
                    .to_string(),
            }
            },
        );
    }
    if settings.contains_key("optimistic_cache") {
        cfg.cache.enabled = scalars::bool_value(
            &settings,
            "optimistic_cache",
            "dns.optimistic_cache",
            diagnostics,
        );
    }
    if let Some(v) = settings.get("optimistic_cache_ttl") {
        let value = v.unquote().raw();
        cfg.cache.ttl = lenient(value.parse().ok(), 60, diagnostics, || {
            ConfigDiagnostic {
            setting: "dns.optimistic_cache_ttl".to_string(),
            value: value.to_string(),
            message: "honk could not parse this value as an unsigned decimal integer in range; using fallback 60"
                .to_string(),
        }
        });
    }
    if let Some(v) = settings.get("optimistic_stale_reply_ttl") {
        let value = v.unquote().raw();
        cfg.cache.stale_reply_ttl = lenient(value.parse().ok(), 30, diagnostics, || {
            ConfigDiagnostic {
                setting: "dns.optimistic_stale_reply_ttl".to_string(),
                value: value.to_string(),
                message: "honk could not parse this value as an unsigned decimal integer in range; using fallback 30"
                    .to_string(),
            }
        });
    }
    if let Some(v) = settings.get("max_cache_size") {
        let value = v.unquote().raw();
        cfg.cache.max_size = lenient(value.parse().ok(), 10000, diagnostics, || {
            ConfigDiagnostic {
            setting: "dns.max_cache_size".to_string(),
            value: value.to_string(),
            message: "honk could not parse this value as an unsigned decimal integer in range; using fallback 10000"
                .to_string(),
        }
        });
    }

    for sub in dns_subs {
        match read::block_header(&sub).unwrap().raw() {
            "upstream" => {
                if !saw_upstream {
                    cfg.upstream.clear();
                    saw_upstream = true;
                }
                cfg.upstream.extend(parse_dns_upstreams(&sub, diagnostics));
            }
            "routing" => {
                let mut blocks = Vec::new();
                let mut lines = Vec::new();
                children(
                    &sub,
                    &["request", "response"],
                    &mut lines,
                    &mut blocks,
                    diagnostics,
                );
                for line in lines {
                    line.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-statement",
                        "DNS routing requires request or response blocks",
                    );
                }
                for block in blocks {
                    parse_dns_routing(&block, &mut cfg.routing, diagnostics);
                }
            }
            "fixed_domain_ttl" => {
                cfg.fixed_domain_ttl
                    .extend(parse_fixed_domain_ttl(&sub, diagnostics));
            }
            _ => {}
        }
    }

    Ok(cfg)
}

fn parse_dns_upstreams(
    section: &Segment<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Vec<crate::dns::DnsUpstream> {
    let mut upstreams = Vec::new();
    for (index, line) in read::child_statements(section, diagnostics)
        .into_iter()
        .enumerate()
    {
        if line.has_error() {
            continue;
        }
        let Some((name, rest)) = line.kv() else {
            continue;
        };
        diagnostics.entry_text(line, index + 1);
        if let Some(comment) = line.trailing_comment() {
            comment.notice(
                diagnostics,
                Severity::Warning,
                "legacy-upstream-comment",
                "upstream comments start at an unquoted token-head `#`",
            );
        }
        let separator = rest
            .find("->")
            .map(|offset| (offset, 2))
            .or_else(|| rest.find("outbound:").map(|offset| (offset, 9)));
        let legacy_separator = rest
            .raw()
            .find("->")
            .map(|offset| (offset, 2))
            .or_else(|| rest.raw().find("outbound:").map(|offset| (offset, 9)));
        if let Some((offset, length)) = legacy_separator.filter(|old| Some(*old) != separator) {
            rest.sub(offset, offset + length).notice(
                diagnostics,
                Severity::Warning,
                "legacy-upstream-separator",
                "quoted URI separators are data; put the detour outside URL quotes",
            );
        }
        let (uri, outbound) = if let Some((offset, length)) = separator {
            let target = rest.sub(offset + length, rest.raw().len()).unquote().raw();
            (
                rest.sub(0, offset).unquote().raw(),
                (length == 9 || !target.is_empty()).then(|| target.to_owned()),
            )
        } else {
            (rest.unquote().raw(), None)
        };
        let (protocol, address) = parse_upstream_uri(uri);
        let (address, explicit_sni) = extract_tls_server_name(address);
        let tls_server_name = explicit_sni.or_else(|| sni_from_upstream_address(&address));
        upstreams.push(crate::dns::DnsUpstream {
            name: name.raw().to_owned(),
            address,
            protocol,
            tls_server_name,
            outbound,
        });
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

fn parse_fixed_domain_ttl(
    section: &Segment<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for (index, line) in read::child_statements(section, diagnostics)
        .into_iter()
        .enumerate()
    {
        if line.has_error() {
            continue;
        }
        let Some((key, value)) = line.kv() else {
            continue;
        };
        diagnostics.entry_text(value, index + 1);
        let extra = value
            .tokens
            .iter()
            .filter(|token| token.span.start < value.span.end && value.span.start < token.span.end)
            .nth(1);
        let scalar = value.unquote();
        let (code, message) = if extra.is_some() {
            (
                "trailing-value",
                "TTL requires exactly one decimal scalar; entry omitted",
            )
        } else if let Ok(ttl) = scalar.raw().parse::<u32>() {
            map.insert(key.unquote().raw().to_owned(), ttl);
            if scalar.span == value.span {
                continue;
            }
            (
                "legacy-ttl-quoting",
                "quoted decimal TTL is accepted; use bare or quoted decimal values",
            )
        } else {
            (
                "invalid-ttl",
                "TTL must be an unsigned 32-bit decimal integer; entry omitted",
            )
        };
        diagnostics.emit(DetailedDiagnostic::warning(
            code,
            diagnostics.source(),
            SettingPath::new("dns")
                .field("fixed_domain_ttl")
                .index(index + 1),
            SafeValue::Ordinal(index + 1),
            message,
        ));
    }
    map
}

fn legacy_comment_has_unquoted_slash(comment: Text<'_, '_>) -> bool {
    let bytes = comment.raw().as_bytes();
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        match bytes[offset] {
            b'\'' | b'"' => {
                let Some(end) = quoted_end(bytes, offset) else {
                    return false;
                };
                offset = end;
            }
            b'/' if bytes[offset + 1] == b'/' => return true,
            _ => offset += 1,
        }
    }
    false
}

fn parse_dns_routing(
    section: &Segment<'_, '_>,
    routing: &mut crate::dns::DnsRouting,
    diagnostics: &mut ParserDiagnostics<'_>,
) {
    let is_response = read::block_header(section).unwrap().raw() == "response";
    let kind = if is_response { "response" } else { "request" };
    for (index, line) in read::child_statements(section, diagnostics)
        .into_iter()
        .enumerate()
    {
        if line.has_error() {
            continue;
        }
        let ordinal = index + 1;
        diagnostics.entry_text(line, ordinal);
        if let Some(comment) = line.trailing_comment() {
            let token = line.comment.expect("trailing comment token");
            let suffix = Text {
                span: token.span,
                ..line
            };
            if line.find("#").is_some()
                || line.source.text().as_bytes()[comment.span.start - 1] != b' '
                || legacy_comment_has_unquoted_slash(suffix)
            {
                comment.notice(
                    diagnostics,
                    Severity::Warning,
                    "legacy-dns-hash",
                    "separate comments with whitespace outside quotes; glued hashes remain data",
                );
            }
        }
        let arrow = line.find("->");
        let fallback = ["fallback:", "default:"]
            .into_iter()
            .find(|prefix| line.raw().starts_with(prefix));
        if let Some(offset) = line.find("//") {
            line.sub(offset, offset + 2).notice(
                diagnostics,
                Severity::Warning,
                "legacy-slash-comment",
                "DNS slash comments are unsupported; use a token-head `#` comment",
            );
            let action = arrow.map(|offset| offset + 2).or(fallback.map(str::len));
            if line.raw().starts_with("//")
                || action.is_some_and(|start| {
                    line.tokens.iter().any(|token| {
                        token.span.start >= line.span.start + start
                            && line.source.raw(token.span).starts_with("//")
                    })
                })
            {
                continue;
            }
        }
        if let Some(prefix) = fallback {
            let target = line.sub(prefix.len(), line.raw().len()).trim();
            if target.raw().is_empty() {
                invalid_dns_rule(diagnostics, kind, ordinal, "incomplete-dns-rule");
            } else if is_response {
                routing.response.fallback = crate::dns::DnsResponseAction::parse(target.raw());
            } else {
                routing.request.fallback = crate::dns::DnsRequestAction::parse(target.raw());
                if let crate::dns::DnsRequestAction::Upstream(name) = &routing.request.fallback {
                    routing.fallback = name.clone();
                }
            }
            continue;
        }
        let Some(arrow) = arrow else {
            invalid_dns_rule(diagnostics, kind, ordinal, "incomplete-dns-rule");
            continue;
        };
        let left = line.sub(0, arrow).trim();
        let right = line.sub(arrow + 2, line.raw().len()).trim();
        if left.raw().is_empty() || right.raw().is_empty() {
            invalid_dns_rule(diagnostics, kind, ordinal, "incomplete-dns-rule");
            continue;
        }
        if let Some(offset) = right.find("->") {
            right.sub(offset, offset + 2).notice(
                diagnostics,
                Severity::Warning,
                "legacy-arrow-target",
                "additional arrows remain literal upstream target data",
            );
        }
        let conditions = parse_dns_conditions(left, is_response, diagnostics, kind, ordinal);
        if conditions.is_empty() {
            continue;
        }
        if is_response {
            routing.response.rules.push(crate::dns::DnsResponseRule {
                conditions,
                action: crate::dns::DnsResponseAction::parse(right.raw()),
            });
        } else {
            routing.request.rules.push(crate::dns::DnsRequestRule {
                conditions,
                action: crate::dns::DnsRequestAction::parse(right.raw()),
            });
        }
    }
}

fn parse_dns_conditions(
    expr: Text<'_, '_>,
    is_response: bool,
    diagnostics: &mut ParserDiagnostics<'_>,
    route_kind: &'static str,
    ordinal: usize,
) -> Vec<crate::dns::DnsCond> {
    let mut conds = Vec::new();
    for part in expr.split("&&") {
        let part = part.trim();
        diagnostics.at_text(part);
        let not = part.raw().starts_with('!');
        let inner = if not {
            part.sub(1, part.raw().len()).trim()
        } else {
            part
        };
        let Some(open) = inner.find("(") else {
            let code = if inner.find(")").is_some() {
                "incomplete-dns-rule"
            } else {
                "invalid-dns-rule"
            };
            invalid_dns_rule(diagnostics, route_kind, ordinal, code);
            return Vec::new();
        };
        let name = inner.sub(0, open).raw();
        if !matches!(name, "qname" | "qtype" | "sip")
            && !(is_response && matches!(name, "upstream" | "ip"))
        {
            let code = if matches!(name, "sub" | "node" | "subnode") {
                "unsupported-dns-condition"
            } else {
                "invalid-dns-rule"
            };
            invalid_dns_rule(diagnostics, route_kind, ordinal, code);
            return Vec::new();
        }
        let body = inner.sub(open + 1, inner.raw().len());
        // First unquoted closer preserves bare regex parentheses as the existing grammar does.
        let Some(close) = body.find(")") else {
            invalid_dns_rule(diagnostics, route_kind, ordinal, "incomplete-dns-rule");
            return Vec::new();
        };
        let tail = body.sub(close + 1, body.raw().len()).trim();
        if !tail.raw().is_empty() {
            diagnostics.at_text(tail);
            invalid_dns_rule(diagnostics, route_kind, ordinal, "trailing-matcher-text");
            return Vec::new();
        }
        let arguments = body.sub(0, close).trim();
        if name == "qtype"
            && arguments.unquote().span != arguments.span
            && arguments.unquote().raw().contains(',')
        {
            arguments.notice(
                diagnostics,
                Severity::Warning,
                "legacy-quoted-list",
                "quoted qtype aggregates remain lists; prefer bare or individually quoted items",
            );
        }
        let args: Vec<_> = arguments
            .split(",")
            .map(Text::unquote)
            .filter(|arg| !arg.raw().is_empty())
            .collect();
        let condition = match name {
            "qname" => crate::dns::DnsCond::Qname {
                not,
                matchers: parse_dns_qname_args(&args),
            },
            "qtype" => {
                let types: Option<Vec<u16>> = args
                    .iter()
                    .flat_map(|argument| argument.raw().split(','))
                    .map(crate::dns::parse_qtype_token)
                    .collect();
                let Some(types) = types else {
                    invalid_dns_rule(diagnostics, route_kind, ordinal, "invalid-qtype");
                    return Vec::new();
                };
                crate::dns::DnsCond::Qtype { not, types }
            }
            "sip" => {
                let args: Vec<_> = args.into_iter().map(|arg| arg.raw().to_owned()).collect();
                if !validate_dns_networks(&args, diagnostics, route_kind, ordinal) {
                    return Vec::new();
                }
                crate::dns::DnsCond::Sip { not, cidrs: args }
            }
            "upstream" => crate::dns::DnsCond::Upstream {
                not,
                names: args.into_iter().map(|arg| arg.raw().to_owned()).collect(),
            },
            "ip" => {
                let (cidrs, geoip) = parse_dns_ip_args(&args);
                if !validate_dns_networks(&cidrs, diagnostics, route_kind, ordinal) {
                    return Vec::new();
                }
                crate::dns::DnsCond::Ip { not, cidrs, geoip }
            }
            _ => unreachable!(),
        };
        conds.push(condition);
    }
    conds
}

fn invalid_dns_rule(
    diagnostics: &mut ParserDiagnostics<'_>,
    route_kind: &'static str,
    ordinal: usize,
    code: &'static str,
) {
    diagnostics.emit(DetailedDiagnostic::warning(
        code,
        diagnostics.source(),
        SettingPath::new("dns")
            .field("routing")
            .field(route_kind)
            .field("rules")
            .index(ordinal),
        SafeValue::Ordinal(ordinal),
        "invalid or unsupported DNS condition; whole rule omitted",
    ));
}

fn validate_dns_networks(
    values: &[String],
    diagnostics: &mut ParserDiagnostics<'_>,
    route_kind: &'static str,
    ordinal: usize,
) -> bool {
    let mut truncated = false;
    for value in values {
        let Some(decoded) = crate::dns::decode_ip_or_cidr(value) else {
            invalid_dns_rule(diagnostics, route_kind, ordinal, "invalid-dns-network");
            return false;
        };
        truncated |= decoded.truncated;
    }
    if truncated {
        diagnostics.emit(DetailedDiagnostic::warning(
            "dns-network-host-bits",
            diagnostics.source(),
            SettingPath::new("dns")
                .field("routing")
                .field(route_kind)
                .field("rules")
                .index(ordinal),
            SafeValue::Ordinal(ordinal),
            "DNS network host bits are truncated to the network prefix",
        ));
    }
    true
}

/// Parse qname(args) into a list of domain matchers.
fn parse_dns_qname_args(args: &[Text<'_, '_>]) -> Vec<crate::dns::DnsDomainMatcher> {
    let mut matchers = Vec::new();
    for a in args {
        let a = a.trim();
        if a.raw().is_empty() {
            continue;
        }
        let prefix = ["geosite:", "keyword:", "full:", "regex:", "suffix:"]
            .into_iter()
            .find(|prefix| a.raw().starts_with(prefix));
        if let Some(prefix) = prefix {
            let value = a.sub(prefix.len(), a.raw().len()).unquote().raw();
            matchers.push(match prefix {
                "geosite:" => crate::dns::DnsDomainMatcher::Geosite(normalize_geosite_code(value)),
                "keyword:" => crate::dns::DnsDomainMatcher::Keyword(value.to_owned()),
                "full:" => crate::dns::DnsDomainMatcher::Full(value.to_owned()),
                "regex:" => crate::dns::DnsDomainMatcher::Regex(value.to_owned()),
                "suffix:" => crate::dns::DnsDomainMatcher::Suffix(value.to_owned()),
                _ => unreachable!(),
            });
        } else {
            // Bare argument → suffix (dae compatible)
            matchers.push(crate::dns::DnsDomainMatcher::Suffix(a.raw().to_owned()));
        }
    }
    matchers
}

/// Parse ip(...) args into (cidrs, geoip_codes).
fn parse_dns_ip_args(args: &[Text<'_, '_>]) -> (Vec<String>, Vec<String>) {
    let mut cidrs = Vec::new();
    let mut geoip = Vec::new();
    for a in args {
        let a = a.trim();
        if a.raw().starts_with("geoip:") {
            let value = a.sub("geoip:".len(), a.raw().len()).unquote().raw();
            geoip.push(value.to_lowercase());
        } else {
            cidrs.push(a.raw().to_owned());
        }
    }
    (cidrs, geoip)
}
