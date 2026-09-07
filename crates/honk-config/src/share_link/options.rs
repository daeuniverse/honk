//! Apply share-link query fields before validating and deriving node identity.

use std::collections::HashMap;

use crate::error::ConfigError;
use crate::node::{Hysteria2Config, Node, OutboundConfig, QuicOptions, VlessConfig};
use crate::types::{NodeProtocol, parse_duration_secs};

type Query = HashMap<String, String>;

pub(super) fn parse_query(
    url: &url::Url,
    protocol: NodeProtocol,
    shadowrocket: bool,
) -> Result<Query, ConfigError> {
    let shadowrocket_vmess = shadowrocket && protocol == NodeProtocol::VMess;
    let mut query = HashMap::new();
    let mut mode_seen = false;
    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        if shadowrocket_vmess && query.get(&key).is_some_and(|previous| previous != &value) {
            return Err(ConfigError::Parse(
                "duplicate VMess share-link parameter".into(),
            ));
        }
        if protocol == NodeProtocol::VLess
            && matches!(key.as_str(), "vless_mode" | "packetEncoding")
        {
            if mode_seen {
                return Err(ConfigError::Parse(
                    "duplicate VLESS share-link mode representation".into(),
                ));
            }
            mode_seen = true;
        }
        query.insert(key, value.into_owned());
    }
    if protocol != NodeProtocol::VLess
        && (query.contains_key("vless_mode")
            || query.get("packetEncoding").is_some_and(|v| v != "none"))
    {
        return Err(ConfigError::Parse(
            "vless_mode/packetEncoding are valid only for VLESS share links".into(),
        ));
    }
    if shadowrocket_vmess {
        if query
            .get("security")
            .is_some_and(|value| !matches!(value.as_str(), "none" | "tls" | "auto" | "aes-128-gcm"))
        {
            return Err(ConfigError::Parse(
                "unsupported encoded VMess security".into(),
            ));
        }
        if ["pbk", "sid", "spx"]
            .iter()
            .any(|key| query.get(*key).is_some_and(|value| !value.is_empty()))
        {
            return Err(ConfigError::Parse(
                "REALITY parameters are unsupported in encoded VMess links".into(),
            ));
        }
        if query.get("alterId").is_some_and(|value| value != "0") {
            return Err(ConfigError::Parse(
                "unsupported VMess share-link option".into(),
            ));
        }
        if query
            .get("allowInsecure")
            .or_else(|| query.get("allow_insecure"))
            .is_some_and(|value| {
                value != "0"
                    && value != "1"
                    && !value.eq_ignore_ascii_case("true")
                    && !value.eq_ignore_ascii_case("false")
            })
        {
            return Err(ConfigError::Parse(
                "unsupported VMess allowInsecure value".into(),
            ));
        }
    }
    Ok(query)
}

pub(super) fn apply_tls(
    node: &mut Node,
    query: &Query,
    shadowrocket: bool,
) -> Result<(), ConfigError> {
    let protocol = node.protocol();
    let shadowrocket_vless = shadowrocket && protocol == NodeProtocol::VLess;
    let shadowrocket_vmess = shadowrocket && protocol == NodeProtocol::VMess;
    let security = query.get("security").map(String::as_str);
    let mut vless_tls = None;
    let mut reality = security == Some("reality");
    if protocol == NodeProtocol::VLess {
        vless_tls = match query.get("tls").map(String::as_str) {
            None => None,
            Some("0") => Some(false),
            Some("1") => Some(true),
            Some(_) => return Err(ConfigError::Parse("unsupported VLESS tls value".into())),
        };
        let reality_fields = ["pbk", "sid", "spx"]
            .iter()
            .any(|key| query.contains_key(*key));
        if reality_fields && security.is_some_and(|value| value != "reality")
            || vless_tls.is_some_and(|enabled| {
                security.is_some_and(|value| (value != "none") != enabled)
                    || (!enabled && reality_fields)
            })
        {
            return Err(ConfigError::Parse(
                "conflicting VLESS TLS parameters".into(),
            ));
        }
        reality |= reality_fields;
    }

    if let Some(tls) = node.tls_mut() {
        tls.enabled = match protocol {
            NodeProtocol::Trojan | NodeProtocol::AnyTLS => true,
            NodeProtocol::VLess => match security {
                Some("none") => false,
                Some(_) => true,
                None => reality || vless_tls.unwrap_or(!shadowrocket_vless),
            },
            NodeProtocol::VMess if shadowrocket_vmess => {
                let security_tls = match security {
                    Some("none") => Some(false),
                    Some("tls") => Some(true),
                    _ => None,
                };
                match query.get("tls").map(String::as_str) {
                    None => security_tls.unwrap_or(false),
                    Some("0") => {
                        if security_tls == Some(true) {
                            return Err(ConfigError::Parse(
                                "conflicting VMess TLS parameters".into(),
                            ));
                        }
                        false
                    }
                    Some("1") => {
                        if security_tls == Some(false) {
                            return Err(ConfigError::Parse(
                                "conflicting VMess TLS parameters".into(),
                            ));
                        }
                        true
                    }
                    Some(_) => {
                        return Err(ConfigError::Parse("unsupported VMess tls value".into()));
                    }
                }
            }
            NodeProtocol::VMess => security.is_some_and(|value| value != "none"),
            _ => tls.enabled,
        };
        tls.sni = query.get("sni").or_else(|| query.get("peer")).cloned();
        if let Some(value) = query
            .get("allowInsecure")
            .or_else(|| query.get("allow_insecure"))
            .or_else(|| query.get("insecure"))
        {
            tls.skip_cert_verify = value == "1" || value.eq_ignore_ascii_case("true");
        }
        tls.pin_sha256 = query
            .get("pinSHA256")
            .or_else(|| query.get("pin_sha256"))
            .cloned();
        if let Some(value) = query.get("ech_config").or_else(|| query.get("echconfig")) {
            tls.ech_enabled = true;
            tls.ech_config = Some(value.clone());
        } else if let Some(value) = query.get("ech") {
            tls.ech_enabled = value == "1" || value.eq_ignore_ascii_case("true");
        }
        if protocol == NodeProtocol::VLess && reality {
            tls.enabled = true;
            tls.reality_public_key = query.get("pbk").cloned();
            tls.reality_short_id = query.get("sid").cloned();
            tls.reality_spider_x = Some(
                query
                    .get("spx")
                    .filter(|value| !value.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "/".to_string()),
            );
        }
    }
    Ok(())
}

pub(super) fn apply_transport(
    node: &mut Node,
    query: &Query,
    shadowrocket: bool,
) -> Result<(), ConfigError> {
    let protocol = node.protocol();
    let shadowrocket_vmess = shadowrocket && protocol == NodeProtocol::VMess;
    let mut host_consumed = false;
    if let Some(transport) = node.transport_mut() {
        if let Some(value) = query.get("type").or_else(|| query.get("network")) {
            transport.transport = value.clone();
        }
        if matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess)
            && let Some(obfs) = query.get("obfs")
        {
            let alias = match obfs.as_str() {
                "" | "none" => "tcp",
                "websocket" => "ws",
                "grpc" => "grpc",
                _ => {
                    return Err(ConfigError::Parse(
                        if protocol == NodeProtocol::VLess {
                            "unsupported VLESS obfs transport"
                        } else {
                            "unsupported VMess obfs transport"
                        }
                        .into(),
                    ));
                }
            };
            if query
                .get("type")
                .or_else(|| query.get("network"))
                .is_some_and(|value| value != alias)
            {
                return Err(ConfigError::Parse(
                    if protocol == NodeProtocol::VLess {
                        "conflicting VLESS transports"
                    } else {
                        "conflicting VMess transports"
                    }
                    .into(),
                ));
            }
            transport.transport = alias.to_string();
        }
        if shadowrocket_vmess && !matches!(transport.transport.as_str(), "tcp" | "ws" | "grpc") {
            return Err(ConfigError::Parse("unsupported VMess transport".into()));
        }
        match transport.transport.as_str() {
            "ws" => {
                if let Some(value) = query.get("host").or_else(|| {
                    (matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess))
                        .then(|| query.get("obfsParam"))
                        .flatten()
                }) {
                    transport.ws_host = Some(value.clone());
                    host_consumed = true;
                }
                transport.ws_path = query.get("path").cloned();
            }
            "grpc" => {
                transport.grpc_service = query
                    .get("serviceName")
                    .or_else(|| query.get("service_name"))
                    .or_else(|| {
                        (matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess)
                            && query.get("obfs").is_some_and(|value| value == "grpc"))
                        .then(|| query.get("path"))
                        .flatten()
                    })
                    .cloned();
            }
            _ => {}
        }
    }
    if !host_consumed
        && node.tls().is_some_and(|tls| tls.sni.is_none())
        && let Some(value) = query.get("host")
        && let Some(tls) = node.tls_mut()
    {
        tls.sni = Some(value.clone());
    }
    if shadowrocket_vmess {
        let network = node
            .transport()
            .map(|transport| transport.transport.clone());
        if let Some(config) = node.vmess_mut() {
            config.network = network;
        }
    }
    Ok(())
}

pub(super) fn apply_protocol(
    node: &mut Node,
    query: &Query,
    embedded_hop_ports: Option<String>,
    shadowrocket: bool,
) -> Result<(), ConfigError> {
    if node.protocol() != NodeProtocol::SS
        && ["plugin", "plugin-opts", "plugin_opts"]
            .iter()
            .any(|key| query.contains_key(*key))
    {
        return Err(ConfigError::Parse(
            "plugin parameters are valid only for Shadowsocks links".into(),
        ));
    }
    match &mut node.outbound {
        OutboundConfig::Shadowsocks(config) => {
            if let Some(value) = query.get("plugin") {
                if let Some((name, options)) = value.split_once(';') {
                    config.plugin = Some(name.to_string());
                    if !options.is_empty() {
                        config.plugin_opts = Some(options.to_string());
                    }
                } else {
                    config.plugin = Some(value.clone());
                }
            }
            if let Some(value) = query
                .get("plugin-opts")
                .or_else(|| query.get("plugin_opts"))
            {
                config.plugin_opts = Some(value.clone());
            }
        }
        OutboundConfig::Vmess(config) if shadowrocket => {
            if let Some(cipher) = query
                .get("encryption")
                .or_else(|| query.get("scy"))
                .or_else(|| {
                    query
                        .get("security")
                        .filter(|value| !matches!(value.as_str(), "none" | "tls"))
                })
            {
                if !matches!(cipher.as_str(), "auto" | "aes-128-gcm") {
                    return Err(ConfigError::Parse(
                        "unsupported VMess share-link cipher".into(),
                    ));
                }
                config.encryption = Some(cipher.clone());
            }
        }
        OutboundConfig::Vless(config) => apply_vless(config, query)?,
        OutboundConfig::Hysteria2(config) => {
            apply_hysteria2(config, query, embedded_hop_ports)?;
            apply_mtu(&mut config.quic, query);
        }
        OutboundConfig::Tuic(config) => {
            config.init_stream_recv_window = query
                .get("initStreamReceiveWindow")
                .and_then(|value| value.parse().ok());
            config.init_conn_recv_window = query
                .get("initConnReceiveWindow")
                .and_then(|value| value.parse().ok());
            config.congestion = query
                .get("congestion_control")
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            config.alpn = query
                .get("alpn")
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            apply_mtu(&mut config.quic, query);
        }
        OutboundConfig::Juicity(config) => apply_mtu(&mut config.quic, query),
        OutboundConfig::AnyTls(config) => {
            config.idle_session_check_interval = query
                .get("idle_session_check_interval")
                .and_then(|value| parse_duration_secs(value));
            config.idle_session_timeout = query
                .get("idle_session_timeout")
                .and_then(|value| parse_duration_secs(value));
            config.min_idle_session = query
                .get("min_idle_session")
                .and_then(|value| value.parse::<u16>().ok())
                .map(usize::from);
        }
        _ => {}
    }
    Ok(())
}

fn apply_hysteria2(
    config: &mut Hysteria2Config,
    query: &Query,
    embedded_hop_ports: Option<String>,
) -> Result<(), ConfigError> {
    if query.get("obfs").is_some_and(|value| value == "salamander") {
        config.obfs = query
            .get("obfs-password")
            .filter(|value| !value.is_empty())
            .cloned();
    }
    config.up_mbps = query.get("upmbps").and_then(|value| value.parse().ok());
    config.down_mbps = query.get("downmbps").and_then(|value| value.parse().ok());
    let mport = query.get("mport").filter(|value| !value.is_empty());
    if mport.is_some() && embedded_hop_ports.is_some() {
        return Err(ConfigError::Parse(
            "hysteria2 port hopping specified in both address and mport".into(),
        ));
    }
    config.port_hopping = mport.cloned().or(embedded_hop_ports);
    config.hop_interval = query.get("mhop").and_then(|value| value.parse().ok());
    config.init_stream_recv_window = query
        .get("initStreamReceiveWindow")
        .and_then(|value| value.parse().ok());
    config.init_conn_recv_window = query
        .get("initConnReceiveWindow")
        .and_then(|value| value.parse().ok());
    config.disable_mtu_discovery = query
        .get("disablePathMTUDiscovery")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    Ok(())
}

fn apply_mtu(quic: &mut QuicOptions, query: &Query) {
    if let Some(mtu) = query
        .get("mtu")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|mtu| (1200..=65527).contains(mtu))
    {
        quic.mtu = Some(mtu);
    }
}

fn apply_vless(config: &mut VlessConfig, query: &Query) -> Result<(), ConfigError> {
    if let Some(parameter) = [
        "mux",
        "smux",
        "multiplex",
        "udp-over-tcp",
        "udp_over_tcp",
        "packet-encoding",
        "packet_encoding",
        "packet-addr",
        "packet_addr",
        "xudp",
        "only-tcp",
        "only_tcp",
        "brutal",
        "brutal-opts",
        "brutal_opts",
        "max-connections",
        "max_connections",
        "min-streams",
        "min_streams",
        "max-streams",
        "max_streams",
    ]
    .into_iter()
    .find(|parameter| query.contains_key(*parameter))
    {
        return Err(ConfigError::Parse(format!(
            "unsupported VLESS share-link parameter '{parameter}'; use vless_mode"
        )));
    }
    if let Some(mode) = query.get("vless_mode") {
        config.mode = mode.parse()?;
    } else if let Some(encoding) = query.get("packetEncoding") {
        match encoding.as_str() {
            "xudp" => config.mode = crate::node::WireMode::Xudp,
            "none" => {}
            _ => {
                return Err(ConfigError::Parse(
                    "unsupported VLESS packetEncoding (expected xudp or none)".into(),
                ));
            }
        }
    }
    config.flow = query.get("flow").cloned();
    // Shadowrocket's exporter maps 1 to retired XTLS Direct and 2 to Vision.
    if let Some(xtls) = query.get("xtls") {
        let flow = match xtls.as_str() {
            "0" => None,
            "2" => Some("xtls-rprx-vision"),
            _ => return Err(ConfigError::Parse("unsupported VLESS xtls value".into())),
        };
        if config.flow.is_some() && config.flow.as_deref().filter(|value| !value.is_empty()) != flow
            || flow.is_some() && !config.tls.enabled
        {
            return Err(ConfigError::Parse(
                "conflicting VLESS flow parameters".into(),
            ));
        }
        config.flow = flow.map(str::to_string);
    }
    config.encryption = query
        .get("encryption")
        .filter(|value| !value.trim().is_empty())
        .cloned();
    Ok(())
}
