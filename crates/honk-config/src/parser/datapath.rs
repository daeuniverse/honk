use super::{ParseFailure, cursor::Segment, diagnostics::ParserDiagnostics, read};
use crate::datapath::{
    Backend, BusyPollConfig, CalibrationStatus, DatapathConfig, DirectProfile, InterfaceRole,
    PollCalibration, PollMode, XdpInterface, XskMode,
};

fn invalid(message: &str) -> ParseFailure {
    crate::ConfigError::Parse(format!("datapath: {message}")).into()
}

pub(super) fn parse_section(
    sections: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<DatapathConfig, ParseFailure> {
    let mut config = DatapathConfig::default();
    let mut seen = [false; 8];
    for section in sections {
        for child in section.body().ok_or_else(|| invalid("expected block"))? {
            if let Some(header) = read::block_header(&child) {
                let index = match header.raw() {
                    "interface" => 2,
                    "firewall" => 3,
                    "nat" => 4,
                    "busy_poll" => 7,
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
                    7 => config.busy_poll = Some(parse_busy_poll(&child)?),
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
                    "poll_mode" => 6,
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
                    6 => {
                        config.poll_mode = Some(match value.unquote().raw() {
                            "event" => PollMode::Event,
                            "adaptive" => PollMode::Adaptive,
                            _ => return Err(invalid("poll_mode must be event or adaptive")),
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

fn integer(value: &str) -> Result<u32, ParseFailure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("polling values must be unsigned decimal integers"));
    }
    value
        .parse()
        .map_err(|_| invalid("polling integer overflow"))
}

fn narrow(value: u32) -> Result<u16, ParseFailure> {
    value
        .try_into()
        .map_err(|_| invalid("polling integer exceeds u16"))
}

fn parse_busy_poll(section: &Segment<'_, '_>) -> Result<BusyPollConfig, ParseFailure> {
    let keys = [
        "pps_enter",
        "pps_exit",
        "observation_window_us",
        "enter_windows",
        "exit_windows",
        "max_busy_us",
        "empty_rounds",
        "budget_window_us",
        "budget_us",
    ];
    let mut values = [None; 9];
    let mut calibration = None;
    for child in section
        .body()
        .ok_or_else(|| invalid("expected busy_poll block"))?
    {
        if let Some(header) = read::block_header(&child) {
            if header.raw() != "calibration" {
                return Err(invalid("unknown busy_poll block"));
            }
            if calibration.is_some() {
                return Err(invalid("duplicate calibration block"));
            }
            calibration = Some(parse_calibration(&child)?);
        } else {
            let (key, value) = read::Text::segment(&child)
                .kv()
                .ok_or_else(|| invalid("expected busy_poll setting: value"))?;
            let index = keys
                .iter()
                .position(|name| *name == key.raw())
                .ok_or_else(|| invalid("unknown busy_poll setting"))?;
            if values[index]
                .replace(integer(value.unquote().raw())?)
                .is_some()
            {
                return Err(invalid("duplicate busy_poll setting"));
            }
        }
    }
    let mut required = [0; 9];
    for (target, value) in required.iter_mut().zip(values) {
        *target = value.ok_or_else(|| invalid("all nine busy_poll integers are required"))?;
    }
    let config = BusyPollConfig {
        pps_enter: required[0],
        pps_exit: required[1],
        observation_window_us: required[2],
        enter_windows: narrow(required[3])?,
        exit_windows: narrow(required[4])?,
        max_busy_us: required[5],
        empty_rounds: narrow(required[6])?,
        budget_window_us: required[7],
        budget_us: required[8],
        calibration,
    };
    config.validate()?;
    Ok(config)
}

fn parse_calibration(section: &Segment<'_, '_>) -> Result<PollCalibration, ParseFailure> {
    let keys = [
        "schema",
        "counting_revision",
        "executable_sha256",
        "context_sha256",
        "parameter_sha256",
        "status",
        "evidence_manifest_sha256",
    ];
    let mut values = [None; 7];
    for child in section
        .body()
        .ok_or_else(|| invalid("expected calibration block"))?
    {
        if child.is_block() || child.body().is_some() {
            return Err(invalid("calibration does not accept nested blocks"));
        }
        let (key, value) = read::Text::segment(&child)
            .kv()
            .ok_or_else(|| invalid("expected calibration setting: value"))?;
        let index = keys
            .iter()
            .position(|name| *name == key.raw())
            .ok_or_else(|| invalid("unknown calibration setting"))?;
        if values[index].replace(value.unquote().raw()).is_some() {
            return Err(invalid("duplicate calibration setting"));
        }
    }
    let mut required = [""; 7];
    for (target, value) in required.iter_mut().zip(values) {
        *target = value.ok_or_else(|| invalid("all calibration fields are required"))?;
    }
    let config = PollCalibration {
        schema: narrow(integer(required[0])?)?,
        counting_revision: integer(required[1])?,
        executable_sha256: required[2].to_owned(),
        context_sha256: required[3].to_owned(),
        parameter_sha256: required[4].to_owned(),
        status: match required[5] {
            "candidate" => CalibrationStatus::Candidate,
            "qualified" => CalibrationStatus::Qualified,
            _ => return Err(invalid("calibration status must be candidate or qualified")),
        },
        evidence_manifest_sha256: required[6].to_owned(),
    };
    config.validate()?;
    Ok(config)
}
