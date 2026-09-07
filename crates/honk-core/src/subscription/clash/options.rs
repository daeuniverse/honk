use honk_config::node::WireMode;
use serde_yaml::{Mapping, Value};

use super::super::yaml_value;
use super::fields::{active, bool_alias, raw_alias, u64_alias};

pub(in crate::subscription) fn parse_vless_external_mode(
    mapping: &Mapping,
) -> Result<WireMode, &'static str> {
    let udp = yaml_value(mapping, "udp")
        .map(|value| value.as_bool().ok_or("VLESS udp must be boolean"))
        .transpose()?;
    if yaml_value(mapping, "packet-encoding").is_some_and(|value| !matches!(value, Value::Null))
        && yaml_value(mapping, "packet_encoding").is_some_and(|value| !matches!(value, Value::Null))
    {
        return Err("duplicate VLESS XUDP representations");
    }

    // Clash treats an empty packet-encoding as omitted. That lets udp=true take
    // its source-format XUDP default, unlike explicit none/legacy or xudp=false.
    let packet_encoding =
        raw_alias(mapping, &["packet-encoding", "packet_encoding"])?.filter(|value| active(value));
    let xudp = yaml_value(mapping, "xudp").filter(|value| match value {
        Value::Null => false,
        Value::String(value) => !value.trim().is_empty(),
        _ => true,
    });
    let packet_encoding_disabled = packet_encoding.is_some_and(|value| {
        value
            .as_str()
            .is_some_and(|encoding| matches!(encoding.trim(), "none" | "legacy"))
    });
    let xudp_enabled = match (packet_encoding, xudp) {
        (Some(value), None) => match value
            .as_str()
            .ok_or("VLESS packet encoding must be a string")?
            .trim()
        {
            "" | "none" | "legacy" => false,
            "xudp" => true,
            _ => return Err("unsupported VLESS packet encoding"),
        },
        (None, Some(value)) => value.as_bool().ok_or("VLESS xudp must be boolean")?,
        (None, None) => false,
        (Some(_), Some(_)) => return Err("duplicate VLESS XUDP representations"),
    };
    let xudp_disabled =
        packet_encoding_disabled || xudp.is_some_and(|value| value.as_bool() == Some(false));

    if let Some(value) =
        raw_alias(mapping, &["packet-addr", "packet_addr"])?.filter(|value| active(value))
        && value.as_bool().ok_or("VLESS packet-addr must be boolean")?
    {
        return Err("unsupported VLESS packet-addr mode");
    }
    if let Some(value) = yaml_value(mapping, "mux").filter(|value| active(value)) {
        let enabled = match value {
            Value::Bool(enabled) => *enabled,
            Value::Mapping(options) => yaml_value(options, "enabled")
                .map(|value| value.as_bool().ok_or("VLESS mux.enabled must be boolean"))
                .transpose()?
                .unwrap_or(false),
            _ => return Err("VLESS mux must be boolean or a mapping"),
        };
        if enabled {
            return Err("top-level VLESS mux is unsupported");
        }
    }

    let mut mux_mode = None;
    if let Some(value) = raw_alias(mapping, &["smux", "multiplex"])?.filter(|value| active(value)) {
        let options = value
            .as_mapping()
            .ok_or("VLESS multiplex settings must be a mapping")?;
        let enabled = yaml_value(options, "enabled")
            .map(|value| {
                value
                    .as_bool()
                    .ok_or("VLESS multiplex.enabled must be boolean")
            })
            .transpose()?
            .unwrap_or(false);
        if enabled {
            let protocol = yaml_value(options, "protocol")
                .map(|value| {
                    value
                        .as_str()
                        .map(str::trim)
                        .ok_or("VLESS multiplex.protocol must be a string")
                })
                .transpose()?
                .filter(|protocol| !protocol.is_empty());
            if protocol.is_some_and(|protocol| protocol != "h2mux") {
                return Err("unsupported VLESS multiplex protocol");
            }
            if bool_alias(options, &["only-tcp", "only_tcp"])? == Some(true) {
                return Err("VLESS multiplex.only-tcp is unsupported");
            }
            if let Some(value) = raw_alias(options, &["brutal", "brutal-opts", "brutal_opts"])? {
                let disabled = match value {
                    Value::Bool(false) => true,
                    Value::Mapping(brutal) if brutal.is_empty() => true,
                    Value::Mapping(brutal) => match yaml_value(brutal, "enabled") {
                        Some(value) => !value
                            .as_bool()
                            .ok_or("VLESS multiplex Brutal enabled must be boolean")?,
                        None => false,
                    },
                    _ => false,
                };
                if !disabled {
                    return Err("VLESS multiplex Brutal is unsupported");
                }
            }
            for keys in [
                ["max-connections", "max_connections"],
                ["min-streams", "min_streams"],
                ["max-streams", "max_streams"],
            ] {
                if u64_alias(options, &keys)?.is_some_and(|limit| limit != 0) {
                    return Err("VLESS multiplex tuning is unsupported");
                }
            }
            let padding = yaml_value(options, "padding")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or("VLESS multiplex.padding must be boolean")
                })
                .transpose()?;
            if protocol.is_none() && padding.is_none() {
                return Err(
                    "enabled VLESS multiplex requires an explicit protocol or padding setting",
                );
            }
            mux_mode = Some(if padding.unwrap_or(false) {
                WireMode::H2muxPadded
            } else {
                WireMode::H2mux
            });
        }
    }

    let mut uot_enabled = false;
    if let Some(value) =
        raw_alias(mapping, &["udp-over-tcp", "udp_over_tcp"])?.filter(|value| active(value))
    {
        match value {
            Value::Bool(enabled) => uot_enabled = *enabled,
            Value::Mapping(options) => {
                uot_enabled = yaml_value(options, "enabled")
                    .map(|value| {
                        value
                            .as_bool()
                            .ok_or("VLESS udp-over-tcp.enabled must be boolean")
                    })
                    .transpose()?
                    .unwrap_or(false);
                if uot_enabled {
                    let version = yaml_value(options, "version")
                        .map(|value| {
                            value
                                .as_u64()
                                .ok_or("VLESS udp-over-tcp.version must be an integer")
                        })
                        .transpose()?
                        .unwrap_or(0);
                    if !matches!(version, 0 | 2) {
                        return Err("unsupported VLESS udp-over-tcp version");
                    }
                }
            }
            _ => return Err("VLESS udp-over-tcp must be boolean or a mapping"),
        }
    }

    if xudp_enabled && (mux_mode.is_some() || uot_enabled) {
        return Err("VLESS XUDP cannot be combined with multiplex or udp-over-tcp");
    }
    if mux_mode.is_some() && uot_enabled {
        return Err("VLESS multiplex and udp-over-tcp cannot both be enabled");
    }
    let mut mode = if xudp_enabled {
        WireMode::Xudp
    } else if let Some(mode) = mux_mode {
        mode
    } else if uot_enabled {
        WireMode::UotV2
    } else {
        WireMode::Legacy
    };
    if udp == Some(true) && mode == WireMode::Legacy {
        if xudp_disabled {
            return Err("VLESS udp=true requires an enabled packet mode");
        }
        mode = WireMode::Xudp;
    }
    if udp == Some(false) && mode != WireMode::Legacy {
        return Err("VLESS packet mode enables UDP but udp is false");
    }
    Ok(mode)
}
