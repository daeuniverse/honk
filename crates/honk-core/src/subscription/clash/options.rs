use honk_config::node::{Udp443Policy, VlessMultiplex, VlessUdpEncoding};
use serde_yaml::{Mapping, Value};

use super::super::yaml_value;
use super::fields::{active, bool_alias, raw_alias, u64_alias};

fn signed_i16(mapping: &Mapping, key: &str) -> Result<i16, &'static str> {
    match yaml_value(mapping, key) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(value)) => value
            .as_i64()
            .and_then(|value| i16::try_from(value).ok())
            .ok_or("VLESS mux concurrency must be a signed 16-bit integer"),
        Some(Value::String(value)) => value
            .trim()
            .parse()
            .map_err(|_| "VLESS mux concurrency must be a signed 16-bit integer"),
        Some(_) => Err("VLESS mux concurrency must be a signed 16-bit integer"),
    }
}

fn parse_xray_multiplex(mapping: &Mapping) -> Result<Option<VlessMultiplex>, &'static str> {
    let Some(value) = yaml_value(mapping, "mux").filter(|value| active(value)) else {
        return Ok(None);
    };
    let Value::Mapping(options) = value else {
        return Err("VLESS mux must be an Xray mux object");
    };
    let enabled = yaml_value(options, "enabled")
        .map(|value| value.as_bool().ok_or("VLESS mux.enabled must be boolean"))
        .transpose()?
        .unwrap_or(false);
    if !enabled {
        return Ok(None);
    }
    for (key, value) in options {
        if !matches!(
            key.as_str(),
            Some("enabled" | "concurrency" | "xudpConcurrency" | "xudpProxyUDP443")
        ) && active(value)
        {
            return Err("unsupported VLESS Xray mux setting");
        }
    }
    let udp443 = match yaml_value(options, "xudpProxyUDP443") {
        None | Some(Value::Null) => Udp443Policy::Reject,
        Some(Value::String(value)) => match value.trim() {
            "reject" => Udp443Policy::Reject,
            "skip" => Udp443Policy::Skip,
            "allow" => Udp443Policy::Allow,
            _ => return Err("unsupported VLESS Xray UDP/443 policy"),
        },
        Some(_) => return Err("VLESS Xray UDP/443 policy must be a string"),
    };
    Ok(Some(VlessMultiplex::xray(
        signed_i16(options, "concurrency")?,
        signed_i16(options, "xudpConcurrency")?,
        udp443,
    )))
}

pub(in crate::subscription) fn parse_vless_external_options(
    mapping: &Mapping,
) -> Result<(VlessUdpEncoding, VlessMultiplex, bool), &'static str> {
    let udp = yaml_value(mapping, "udp")
        .map(|value| value.as_bool().ok_or("VLESS udp must be boolean"))
        .transpose()?;
    if yaml_value(mapping, "packet-encoding").is_some_and(|value| !matches!(value, Value::Null))
        && yaml_value(mapping, "packet_encoding").is_some_and(|value| !matches!(value, Value::Null))
    {
        return Err("duplicate VLESS XUDP representations");
    }

    // Clash treats an empty packet-encoding as omitted, while none/legacy and
    // xudp=false explicitly select the native VLESS packet command.
    let packet_encoding =
        raw_alias(mapping, &["packet-encoding", "packet_encoding"])?.filter(|value| {
            value
                .as_str()
                .is_none_or(|encoding| !encoding.trim().is_empty())
        });
    let xudp = yaml_value(mapping, "xudp").filter(|value| match value {
        Value::Null => false,
        Value::String(value) => !value.trim().is_empty(),
        _ => true,
    });
    let packet_encoding = match (packet_encoding, xudp) {
        (Some(value), None) => match value
            .as_str()
            .ok_or("VLESS packet encoding must be a string")?
            .trim()
        {
            "none" | "legacy" => Some(VlessUdpEncoding::Native),
            "xudp" => Some(VlessUdpEncoding::Xudp),
            _ => return Err("unsupported VLESS packet encoding"),
        },
        (None, Some(value)) => Some(if value.as_bool().ok_or("VLESS xudp must be boolean")? {
            VlessUdpEncoding::Xudp
        } else {
            VlessUdpEncoding::Native
        }),
        (None, None) => None,
        (Some(_), Some(_)) => return Err("duplicate VLESS XUDP representations"),
    };

    if let Some(value) =
        raw_alias(mapping, &["packet-addr", "packet_addr"])?.filter(|value| active(value))
        && value.as_bool().ok_or("VLESS packet-addr must be boolean")?
    {
        return Err("unsupported VLESS packet-addr mode");
    }

    let xray_multiplex = parse_xray_multiplex(mapping)?;
    let mut h2_multiplex = None;
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
            h2_multiplex = Some(VlessMultiplex::H2 {
                padding: padding.unwrap_or(false),
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

    if h2_multiplex.is_some() && xray_multiplex.is_some() {
        return Err("VLESS H2 and Xray multiplex cannot both be enabled");
    }
    if packet_encoding == Some(VlessUdpEncoding::Xudp) && (h2_multiplex.is_some() || uot_enabled) {
        return Err("VLESS XUDP cannot be combined with H2 multiplex or udp-over-tcp");
    }
    if uot_enabled && (h2_multiplex.is_some() || xray_multiplex.is_some()) {
        return Err("VLESS multiplex and udp-over-tcp cannot both be enabled");
    }

    let wrapper_enabled = h2_multiplex.is_some() || xray_multiplex.is_some() || uot_enabled;
    let udp_enabled =
        udp != Some(false) && (udp == Some(true) || packet_encoding.is_some() || wrapper_enabled);
    let multiplex = xray_multiplex
        .or(h2_multiplex)
        .unwrap_or(VlessMultiplex::Off);
    let udp_encoding = if uot_enabled {
        VlessUdpEncoding::UotV2
    } else if let Some(packet_encoding) = packet_encoding {
        packet_encoding
    } else if udp == Some(true) && multiplex == VlessMultiplex::Off {
        VlessUdpEncoding::Xudp
    } else {
        VlessUdpEncoding::Auto
    };
    Ok((udp_encoding, multiplex, udp_enabled))
}
