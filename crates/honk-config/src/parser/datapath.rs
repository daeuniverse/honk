use super::{ParseFailure, cursor::Segment, diagnostics::ParserDiagnostics, read};
use crate::datapath::{
    Backend, DatapathConfig, DirectProfile, InterfaceRole, XdpInterface, XskMode,
};

fn invalid(message: &str) -> ParseFailure {
    crate::ConfigError::Parse(format!("datapath: {message}")).into()
}

pub(super) fn parse_section(
    sections: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<DatapathConfig, ParseFailure> {
    let mut config = DatapathConfig::default();
    let mut seen = [false; 6];
    for section in sections {
        for child in section.body().ok_or_else(|| invalid("expected block"))? {
            if let Some(header) = read::block_header(&child) {
                let index = match header.raw() {
                    "interface" => 2,
                    "firewall" => 3,
                    "nat" => 4,
                    _ => return Err(invalid("unknown nested block")),
                };
                if std::mem::replace(&mut seen[index], true) {
                    return Err(invalid("duplicate nested block"));
                }
                match index {
                    2 => {
                        for entry in child
                            .body()
                            .ok_or_else(|| invalid("expected interface block"))?
                        {
                            if entry.is_block() || entry.body().is_some() {
                                let mut diagnostic = entry.source().diagnostic(
                                    entry.header_span(),
                                    crate::diagnostic::Severity::Error,
                                    "nested-interface-block",
                                    "interface entries must be name: lan or wan without a body",
                                );
                                diagnostic.setting =
                                    crate::diagnostic::SettingPath::new("datapath")
                                        .field("interface");
                                diagnostic.terminal = true;
                                return Err(crate::error::DetailedConfigError {
                                    category: crate::error::ErrorCategory::Parse,
                                    diagnostic: Box::new(diagnostic),
                                }
                                .into());
                            }
                            let (name, role) = read::Text::segment(&entry)
                                .kv()
                                .ok_or_else(|| invalid("expected interface: lan or wan"))?;
                            let role = match role.unquote().raw() {
                                "lan" => InterfaceRole::Lan,
                                "wan" => InterfaceRole::Wan,
                                _ => return Err(invalid("unknown interface role")),
                            };
                            config.interfaces.push(XdpInterface {
                                name: name.unquote().raw().to_owned(),
                                role,
                            });
                        }
                    }
                    3 => {
                        config.firewall = Some(super::firewall::parse_firewall(
                            std::slice::from_ref(&child),
                            diagnostics,
                        )?)
                    }
                    4 => {
                        config.nat =
                            super::firewall::parse_nat(std::slice::from_ref(&child), diagnostics)?
                    }
                    _ => unreachable!(),
                }
            } else {
                let (key, value) = read::Text::segment(&child)
                    .kv()
                    .ok_or_else(|| invalid("expected setting: value"))?;
                let index = match key.raw() {
                    "backend" => 0,
                    "direct" => 1,
                    "xsk_mode" => 5,
                    _ => return Err(invalid("unknown setting")),
                };
                if std::mem::replace(&mut seen[index], true) {
                    return Err(invalid("duplicate setting"));
                }
                match index {
                    0 => {
                        config.backend = match value.unquote().raw() {
                            "tc" => Backend::Tc,
                            "xdp" => Backend::Xdp,
                            _ => return Err(invalid("backend must be tc or xdp")),
                        }
                    }
                    1 => {
                        config.direct = Some(match value.unquote().raw() {
                            "core" => DirectProfile::Core,
                            "endpoint" => DirectProfile::Endpoint,
                            _ => {
                                return Err(invalid(
                                    "direct must be core or endpoint; native continuation is unavailable",
                                ));
                            }
                        })
                    }
                    5 => {
                        config.xsk_mode = Some(match value.unquote().raw() {
                            "copy" => XskMode::Copy,
                            "zerocopy" => XskMode::ZeroCopy,
                            _ => return Err(invalid("xsk_mode must be copy or zerocopy")),
                        });
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
    config.validate()?;
    Ok(config)
}
