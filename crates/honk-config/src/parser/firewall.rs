//! Typed actions with the traffic parser's canonical condition grammar.
use super::{
    ParseFailure,
    cursor::{BodySyntax, Segment},
    diagnostics::ParserDiagnostics,
    read,
    routing::{Expression, parse_condition_strict},
};
use crate::{ConfigError, firewall::*, routing::RoutingCondition};

fn invalid(message: &str) -> ParseFailure {
    ConfigError::Parse(format!("datapath firewall/NAT: {message}")).into()
}

pub(super) fn parse_firewall(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<FirewallConfig, ParseFailure> {
    let mut config = FirewallConfig::default();
    let mut seen = [false; 2];
    for root in section {
        for child in root
            .body()
            .ok_or_else(|| invalid("expected firewall block"))?
        {
            let header = read::block_header(&child)
                .ok_or_else(|| invalid("expected original or forward block"))?;
            let (index, chain) = match header.raw() {
                "original" => (0, &mut config.original),
                "forward" => (1, &mut config.forward),
                _ => return Err(invalid("unknown firewall block")),
            };
            if std::mem::replace(&mut seen[index], true) {
                return Err(invalid("duplicate firewall chain"));
            }
            let mut default_seen = false;
            statements(&child, diagnostics, |ingress, left, right| {
                let verdict = match right.as_str() {
                    "allow" => FirewallVerdict::Allow,
                    "drop" => FirewallVerdict::Drop,
                    "reject" => FirewallVerdict::Reject,
                    _ => return Err(invalid("expected allow, drop or reject")),
                };
                if let Some(condition) = left {
                    chain.rules.push(FirewallRule {
                        ingress,
                        condition,
                        verdict,
                    });
                } else {
                    if std::mem::replace(&mut default_seen, true) {
                        return Err(invalid("duplicate chain default"));
                    }
                    chain.default = verdict;
                }
                Ok(())
            })?;
        }
    }
    Ok(config)
}

pub(super) fn parse_nat(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<NatConfig, ParseFailure> {
    let mut config = NatConfig::default();
    let mut seen = [false; 2];
    for root in section {
        for child in root.body().ok_or_else(|| invalid("expected NAT block"))? {
            let header = read::block_header(&child)
                .ok_or_else(|| invalid("expected prerouting or postrouting block"))?;
            let index = match header.raw() {
                "prerouting" => 0,
                "postrouting" => 1,
                _ => return Err(invalid("unknown NAT block")),
            };
            if std::mem::replace(&mut seen[index], true) {
                return Err(invalid("duplicate NAT chain"));
            }
            statements(&child, diagnostics, |ingress, condition, action| {
                if ingress.is_some() {
                    return Err(invalid("zone prefixes belong to firewall chains"));
                }
                let condition =
                    condition.ok_or_else(|| invalid("NAT chains have no default action"))?;
                let (name, args) = action
                    .split_once('(')
                    .ok_or_else(|| invalid("expected typed NAT action"))?;
                let args = args
                    .strip_suffix(')')
                    .ok_or_else(|| invalid("unterminated NAT action"))?;
                if index == 0 && name.trim() == "dnat" {
                    let (address, port) = match args.trim().split_once(':') {
                        Some((ip, port)) => (
                            ip.trim(),
                            Some(
                                port.trim()
                                    .parse()
                                    .map_err(|_| invalid("invalid DNAT port"))?,
                            ),
                        ),
                        None => (args.trim(), None),
                    };
                    config.prerouting.push(DnatRule {
                        condition,
                        action: DestinationNat {
                            address: address.parse().map_err(|_| invalid("DNAT requires IPv4"))?,
                            port,
                        },
                    });
                } else if index == 1 {
                    let action = match name.trim() {
                        "snat" => {
                            let (ip, ports) = match args.split_once(',') {
                                Some((ip, pool)) => (ip.trim(), Some(port_pool(pool)?)),
                                None => (args.trim(), None),
                            };
                            SourceNat::Snat {
                                address: ip.parse().map_err(|_| invalid("SNAT requires IPv4"))?,
                                ports,
                            }
                        }
                        "masquerade" => SourceNat::Masquerade {
                            ports: if args.trim().is_empty() {
                                PortPool::default()
                            } else {
                                port_pool(args)?
                            },
                        },
                        _ => return Err(invalid("postrouting requires snat or masquerade")),
                    };
                    config.postrouting.push(SnatRule { condition, action });
                } else {
                    return Err(invalid("prerouting requires dnat"));
                }
                Ok(())
            })?;
        }
    }
    Ok(config)
}

fn port_pool(value: &str) -> Result<PortPool, ParseFailure> {
    let value = value.trim();
    let (first, last) = value.split_once('-').unwrap_or((value, value));
    let pool = PortPool {
        first: first
            .trim()
            .parse()
            .map_err(|_| invalid("invalid first port"))?,
        last: last
            .trim()
            .parse()
            .map_err(|_| invalid("invalid last port"))?,
    };
    if pool.first == 0 || pool.first > pool.last {
        return Err(invalid("invalid port range"));
    }
    Ok(pool)
}

fn statements(
    section: &Segment<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
    mut consume: impl FnMut(
        Option<crate::datapath::InterfaceRole>,
        Option<RoutingCondition>,
        String,
    ) -> Result<(), ParseFailure>,
) -> Result<(), ParseFailure> {
    for child in section
        .body_with(BodySyntax::Expressions)
        .into_iter()
        .flatten()
    {
        if child.is_block() {
            let mut diagnostic = child.source().diagnostic(
                child.header_span(),
                crate::diagnostic::Severity::Error,
                "nested-security-block",
                "firewall and NAT chains do not accept nested blocks",
            );
            diagnostic.setting = crate::diagnostic::SettingPath::new("datapath");
            diagnostic.terminal = true;
            return Err(crate::error::DetailedConfigError {
                category: crate::error::ErrorCategory::Parse,
                diagnostic: Box::new(diagnostic),
            }
            .into());
        }
    }
    let lines = read::child_statements(section, diagnostics, BodySyntax::Expressions);
    let mut start = 0;
    let mut depth = 0usize;
    for end in 0..lines.len() {
        if start < end && lines[start].span.source != lines[end].span.source {
            return Err(invalid("unterminated rule at source boundary"));
        }
        for (_, byte) in Expression::new(&lines[end..=end]).parentheses() {
            if byte == b'(' {
                depth += 1;
            } else {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid("unmatched closing parenthesis"))?;
            }
        }
        if depth != 0 {
            continue;
        }
        let expression = Expression::new(&lines[start..=end]).trim();
        start = end + 1;
        if expression.starts_with("default:") {
            consume(
                None,
                None,
                expression
                    .sub(expression.span.start + 8, expression.span.end)
                    .trim()
                    .value()
                    .into_owned(),
            )?;
        } else {
            let arrow = expression
                .find("->")
                .ok_or_else(|| invalid("rule requires an arrow"))?;
            let mut left = expression.sub(expression.span.start, arrow).trim();
            let ingress = if left.starts_with("lan:") {
                Some(crate::datapath::InterfaceRole::Lan)
            } else if left.starts_with("wan:") {
                Some(crate::datapath::InterfaceRole::Wan)
            } else {
                None
            };
            if ingress.is_some() {
                left = left.sub(left.span.start + 4, left.span.end).trim();
            }
            if left.is_empty() {
                return Err(invalid("rule requires a condition"));
            }
            let right = expression.sub(arrow + 2, expression.span.end).trim();
            consume(
                ingress,
                Some(parse_condition_strict(left, end + 1)?),
                right.value().into_owned(),
            )?;
        }
    }
    if depth != 0 {
        return Err(invalid("unterminated rule"));
    }
    Ok(())
}
