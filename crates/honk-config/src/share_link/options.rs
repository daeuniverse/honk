//! Apply share-link query fields before validating and deriving node identity.

use crate::diagnostic::{SettingPath, SourceRef};
use crate::error::{ConfigError, DetailedConfigError, ErrorCategory};
use crate::node::{
    Hysteria2Config, Node, OutboundConfig, QuicOptions, Udp443Policy, VlessConfig, VlessMultiplex,
    VlessUdpEncoding,
};
use crate::options::vocab::{
    coalesce_equal, optional_flow, optional_text, stream_transport, verification_text, vmess_cipher,
};
use crate::types::{NodeProtocol, parse_duration_secs};

#[derive(Default)]
pub(super) struct Query(Vec<(String, String)>);

impl Query {
    fn push(&mut self, key: String, value: String) {
        self.0.push((key, value));
    }

    pub(super) fn get(&self, key: &str) -> Option<&String> {
        self.0
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    fn values<'a>(&'a self, key: &str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str())
    }

    fn verification_values_with_indices(&self) -> impl Iterator<Item = (usize, &str)> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, (key, _))| {
                matches!(
                    key.as_str(),
                    "allowInsecure" | "allow_insecure" | "insecure"
                )
            })
            .map(|(index, (_, value))| (index, value.as_str()))
    }

    fn contains_key(&self, key: &str) -> bool {
        self.0.iter().any(|(candidate, _)| candidate == key)
    }
}

fn query_error(
    source: &SourceRef,
    fields: &[&'static str],
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Parse,
        code,
        source.clone(),
        fields
            .iter()
            .fold(SettingPath::new("nodes"), |path, field| path.field(field)),
        message,
    )
}

pub(super) fn parse_query(
    url: &url::Url,
    protocol: NodeProtocol,
    shadowrocket: bool,
    source: &SourceRef,
) -> Result<Query, DetailedConfigError> {
    let legacy = |error| DetailedConfigError::from_legacy(error, source.clone());
    let shadowrocket_vmess = shadowrocket && protocol == NodeProtocol::VMess;
    let mut query = Query::default();
    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        if shadowrocket_vmess
            && !matches!(
                key.as_str(),
                "sni"
                    | "peer"
                    | "allowInsecure"
                    | "allow_insecure"
                    | "insecure"
                    | "type"
                    | "network"
                    | "obfs"
                    | "scy"
                    | "encryption"
            )
            && query.get(&key).is_some_and(|previous| {
                previous != &value
                    && !(key == "security"
                        && vmess_cipher([previous.as_str(), value.as_ref()]).is_ok())
            })
        {
            return Err(legacy(ConfigError::Parse(
                "duplicate VMess share-link parameter".into(),
            )));
        }
        if protocol == NodeProtocol::VLess && key == "vless_mode" {
            return Err(query_error(
                source,
                &["vless_mode"],
                "removed-vless-mode",
                "VLESS vless_mode was removed; use packetEncoding and mux",
            ));
        }
        query.push(key, value.into_owned());
    }
    if protocol != NodeProtocol::VLess
        && (query.contains_key("vless_mode")
            || query.get("packetEncoding").is_some_and(|v| v != "none"))
    {
        return Err(legacy(ConfigError::Parse(
            "vless_mode/packetEncoding are valid only for VLESS share links".into(),
        )));
    }
    if shadowrocket_vmess {
        vmess_cipher(
            query
                .values("security")
                .filter(|value| !matches!(*value, "none" | "tls")),
        )
        .map_err(|reason| legacy(ConfigError::Parse(reason.into())))?;
        if ["pbk", "sid", "spx"]
            .iter()
            .any(|key| query.get(key).is_some_and(|value| !value.is_empty()))
        {
            return Err(legacy(ConfigError::Parse(
                "REALITY parameters are unsupported in encoded VMess links".into(),
            )));
        }
        if query.get("alterId").is_some_and(|value| value != "0") {
            return Err(legacy(ConfigError::Parse(
                "unsupported VMess share-link option".into(),
            )));
        }
    }
    Ok(query)
}

pub(super) fn apply_tls(
    node: &mut Node,
    query: &Query,
    shadowrocket: bool,
    source: &crate::diagnostic::SourceRef,
    emit: &mut impl FnMut(crate::diagnostic::DetailedDiagnostic),
) -> Result<(), DetailedConfigError> {
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
            Some(_) => return Err(super::invalid_link(source)),
        };
        let reality_fields = ["pbk", "sid", "spx"]
            .iter()
            .any(|key| query.contains_key(key));
        if reality_fields && security.is_some_and(|value| value != "reality")
            || vless_tls.is_some_and(|enabled| {
                security.is_some_and(|value| (value != "none") != enabled)
                    || (!enabled && reality_fields)
            })
        {
            return Err(super::invalid_link(source));
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
                            return Err(super::invalid_link(source));
                        }
                        false
                    }
                    Some("1") => {
                        if security_tls == Some(false) {
                            return Err(super::invalid_link(source));
                        }
                        true
                    }
                    Some(_) => {
                        return Err(super::invalid_link(source));
                    }
                }
            }
            NodeProtocol::VMess => security.is_some_and(|value| value != "none"),
            _ => tls.enabled,
        };
        tls.sni = optional_text(
            query
                .values("sni")
                .map(Some)
                .chain(query.values("peer").map(Some)),
        )
        .map_err(|_| {
            query_error(
                source,
                &["sni"],
                "invalid-config-value",
                "conflicting TLS server name aliases",
            )
        })?
        .map(str::to_string);
        let mut verification = None;
        for (ordinal, value) in query.verification_values_with_indices() {
            let parsed = verification_text(value).map_err(|_| {
                query_error(
                    source,
                    &["skip_cert_verify"],
                    "invalid-config-value",
                    "certificate verification aliases must be valid agreeing booleans",
                )
            })?;
            if let Some(previous) = verification {
                if previous != parsed {
                    return Err(query_error(
                        source,
                        &["skip_cert_verify"],
                        "invalid-config-value",
                        "certificate verification aliases must be valid agreeing booleans",
                    ));
                }
            } else {
                verification = Some(parsed);
            }
            if value.trim().eq_ignore_ascii_case("yes") || value.trim().eq_ignore_ascii_case("on") {
                let mut warning = crate::diagnostic::DetailedDiagnostic::warning(
                    "legacy-config-warning",
                    source.clone(),
                    crate::diagnostic::SettingPath::new("nodes").field("skip_cert_verify"),
                    crate::diagnostic::SafeValue::Redacted,
                    "yes/on now disables certificate verification; use true or false explicitly",
                );
                warning.entry_index = Some(ordinal + 1);
                emit(warning);
            }
        }
        if let Some(value) = verification {
            tls.skip_cert_verify = value;
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
fn resolve_stream_transport<'a>(
    query: &'a Query,
    protocol: NodeProtocol,
    source: &SourceRef,
) -> Result<Option<&'a str>, DetailedConfigError> {
    let invalid = || {
        query_error(
            source,
            &["transport"],
            "invalid-config-value",
            "stream transport must be tcp, ws, or grpc; aliases must agree",
        )
    };
    let mut resolved = None;
    for (key, value) in &query.0 {
        let canonical = match key.as_str() {
            "type" | "network" => stream_transport(value).map_err(|_| invalid())?,
            "obfs" if matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess) => {
                match value.as_str() {
                    "" | "none" => "tcp",
                    "websocket" => "ws",
                    "grpc" => "grpc",
                    _ => return Err(invalid()),
                }
            }
            _ => continue,
        };
        if resolved.is_some_and(|previous| previous != canonical) {
            return Err(invalid());
        }
        resolved = Some(canonical);
    }
    Ok(query
        .get("type")
        .or_else(|| query.get("network"))
        .map(String::as_str)
        .or(resolved))
}

pub(super) fn apply_transport(
    node: &mut Node,
    query: &Query,
    source: &SourceRef,
) -> Result<(), DetailedConfigError> {
    let protocol = node.protocol();
    let host_fallback = query.get("host").map(String::as_str);
    let host_sni_fallback =
        optional_text([host_fallback]).map_err(|_| super::invalid_link(source))?;
    let obfs_host = if matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess) {
        query.get("obfsParam").map(String::as_str)
    } else {
        None
    };
    let mut host_consumed = false;
    if let Some(transport) = node.transport_mut() {
        if let Some(value) = resolve_stream_transport(query, protocol, source)? {
            transport.transport = value.to_string();
        }
        let transport_kind = stream_transport(&transport.transport).map_err(|_| {
            query_error(
                source,
                &["transport"],
                "invalid-config-value",
                "stream transport must be tcp, ws, or grpc; aliases must agree",
            )
        })?;
        match transport_kind {
            "ws" => {
                if let Some(value) = host_fallback.or(obfs_host) {
                    transport.ws_host = Some(value.to_string());
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
                            && query.values("obfs").any(|value| value == "grpc"))
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
        && let Some(value) = host_sni_fallback
        && let Some(tls) = node.tls_mut()
    {
        tls.sni = Some(value.to_string());
    }
    Ok(())
}

pub(super) fn apply_protocol(
    node: &mut Node,
    query: &Query,
    embedded_hop_ports: Option<String>,
    shadowrocket: bool,
    source: &crate::diagnostic::SourceRef,
    emit: &mut impl FnMut(crate::diagnostic::DetailedDiagnostic),
) -> Result<(), DetailedConfigError> {
    let legacy = |error| DetailedConfigError::from_legacy(error, source.clone());
    if node.protocol() != NodeProtocol::SS
        && ["plugin", "plugin-opts", "plugin_opts"]
            .iter()
            .any(|key| query.contains_key(key))
    {
        return Err(super::invalid_link(source));
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
            config.encryption = vmess_cipher(
                query.values("encryption").chain(query.values("scy")).chain(
                    query
                        .values("security")
                        .filter(|value| !matches!(*value, "none" | "tls")),
                ),
            )
            .map_err(|reason| legacy(ConfigError::Parse(reason.into())))?
            .map(str::to_owned)
            .or_else(|| config.encryption.take());
        }
        OutboundConfig::Vless(config) => apply_vless(config, query, source)?,
        OutboundConfig::Hysteria2(config) => {
            apply_hysteria2(config, query, embedded_hop_ports).map_err(legacy)?;
            for (ordinal, (key, value)) in query.0.iter().enumerate() {
                if key == "mhop" && value.parse::<u64>().is_err() {
                    let mut warning = crate::diagnostic::DetailedDiagnostic::warning(
                        "legacy-config-warning",
                        source.clone(),
                        crate::diagnostic::SettingPath::new("nodes").field("hy2_hop_interval"),
                        crate::diagnostic::SafeValue::Redacted,
                        "ignored mhop value; share links require unsigned integer seconds",
                    );
                    warning.entry_index = Some(ordinal + 1);
                    emit(warning);
                }
            }
            apply_mtu(&mut config.quic, query);
        }
        OutboundConfig::Tuic(config) => {
            for value in query
                .values("udp-relay-mode")
                .chain(query.values("udp_relay_mode"))
            {
                if !matches!(value, "" | "native") {
                    return Err(legacy(ConfigError::Parse(
                        "unsupported TUIC UDP relay mode".into(),
                    )));
                }
            }
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
    let mut obfs = false;
    for value in query.values("obfs") {
        match value {
            "" => {}
            "salamander" => obfs = true,
            _ => {
                return Err(ConfigError::Parse(
                    "unsupported Hysteria2 obfuscation".into(),
                ));
            }
        }
    }
    let mut password = None;
    for value in query
        .values("obfs-password")
        .chain(query.values("obfs_password"))
    {
        if password.is_some_and(|previous| previous != value) {
            return Err(ConfigError::Parse(
                "conflicting Hysteria2 obfuscation passwords".into(),
            ));
        }
        password = Some(value);
    }
    if obfs {
        config.obfs = password
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
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

fn apply_vless(
    config: &mut VlessConfig,
    query: &Query,
    source: &SourceRef,
) -> Result<(), DetailedConfigError> {
    let invalid = |fields: &[&'static str], message| {
        query_error(source, fields, "invalid-config-value", message)
    };
    if let Some(parameter) = [
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
    .find(|parameter| query.contains_key(parameter))
    {
        let (field, message) = match parameter {
            "udp-over-tcp" | "udp_over_tcp" | "packet-encoding" | "packet_encoding"
            | "packet-addr" | "packet_addr" | "xudp" => (
                "packet_encoding",
                "unsupported VLESS UDP encoding alias; use packetEncoding=auto, none, xudp, or uot-v2",
            ),
            "only-tcp" | "only_tcp" => (
                "network",
                "unsupported VLESS network alias; use udp=0 to disable UDP",
            ),
            _ => (
                "multiplex",
                "unsupported VLESS multiplex parameter; use mux=off, h2mux, or xray and its supported controls",
            ),
        };
        return Err(query_error(
            source,
            &[field],
            "unsupported-vless-parameter",
            message,
        ));
    }
    const CONTROLS: [(&str, &[&str]); 6] = [
        ("packetEncoding", &["packet_encoding"]),
        ("mux", &["multiplex"]),
        ("padding", &["multiplex", "padding"]),
        ("concurrency", &["multiplex", "tcp"]),
        ("xudpConcurrency", &["multiplex", "udp"]),
        ("xudpProxyUDP443", &["multiplex", "udp443"]),
    ];
    for (parameter, fields) in CONTROLS {
        if query.values(parameter).nth(1).is_some() {
            return Err(query_error(
                source,
                fields,
                "duplicate-vless-parameter",
                "VLESS share-link controls must occur only once",
            ));
        }
    }

    if let Some(encoding) = query.get("packetEncoding") {
        config.udp_encoding = match encoding.as_str() {
            "auto" => VlessUdpEncoding::Auto,
            "none" => VlessUdpEncoding::Native,
            "xudp" => VlessUdpEncoding::Xudp,
            "uot-v2" => VlessUdpEncoding::UotV2,
            _ => {
                return Err(invalid(
                    &["packet_encoding"],
                    "VLESS packetEncoding must be auto, none, xudp, or uot-v2",
                ));
            }
        };
    }

    let mux = query.get("mux").map(String::as_str).unwrap_or("off");
    let xray_control = CONTROLS[3..]
        .iter()
        .find(|(parameter, _)| query.contains_key(parameter));
    config.multiplex = match mux {
        "off" => {
            if let Some((_, fields)) = query
                .contains_key("padding")
                .then_some(&CONTROLS[2])
                .or(xray_control)
            {
                return Err(invalid(
                    fields,
                    "VLESS multiplex tuning requires an enabled mux; padding uses h2mux and concurrency/UDP policy use xray",
                ));
            }
            VlessMultiplex::Off
        }
        "h2mux" => {
            if let Some((_, fields)) = xray_control {
                return Err(invalid(
                    fields,
                    "VLESS concurrency and UDP policy controls require mux=xray",
                ));
            }
            let padding = match query.get("padding").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => {
                    return Err(invalid(
                        &["multiplex", "padding"],
                        "VLESS padding must be true or false",
                    ));
                }
            };
            VlessMultiplex::H2 { padding }
        }
        "xray" => {
            if query.contains_key("padding") {
                return Err(invalid(
                    &["multiplex", "padding"],
                    "VLESS padding requires mux=h2mux",
                ));
            }
            let concurrency = query
                .get("concurrency")
                .map(|value| value.parse::<i16>())
                .transpose()
                .map_err(|_| {
                    invalid(
                        &["multiplex", "tcp"],
                        "VLESS concurrency must be an integer from -32768 to 32767",
                    )
                })?
                .unwrap_or(0);
            let xudp_concurrency = query
                .get("xudpConcurrency")
                .map(|value| value.parse::<i16>())
                .transpose()
                .map_err(|_| {
                    invalid(
                        &["multiplex", "udp"],
                        "VLESS xudpConcurrency must be an integer from -32768 to 32767",
                    )
                })?
                .unwrap_or(0);
            let udp443 = match query.get("xudpProxyUDP443").map(String::as_str) {
                None | Some("reject") => Udp443Policy::Reject,
                Some("skip") => Udp443Policy::Skip,
                Some("allow") => Udp443Policy::Allow,
                Some(_) => {
                    return Err(invalid(
                        &["multiplex", "udp443"],
                        "VLESS xudpProxyUDP443 must be reject, skip, or allow",
                    ));
                }
            };
            VlessMultiplex::xray(concurrency, xudp_concurrency, udp443)
        }
        _ => {
            return Err(invalid(
                &["multiplex"],
                "VLESS mux must be off, h2mux, or xray",
            ));
        }
    };

    if let Some(enabled) = coalesce_equal(
        query.values("udp").map(|value| {
            if value == "1" || value.eq_ignore_ascii_case("true") {
                Ok(Some(true))
            } else if value == "0" || value.eq_ignore_ascii_case("false") {
                Ok(Some(false))
            } else {
                Err("unsupported VLESS udp value (expected 1/true or 0/false)")
            }
        }),
        "conflicting VLESS udp parameters",
    )
    .map_err(|_| {
        invalid(
            &["network"],
            "VLESS udp must be 1/true or 0/false; repeated values must agree",
        )
    })? {
        config.network = (!enabled).then(|| "tcp".to_string());
    }
    let flow_error = |category| {
        let mut error = invalid(
            &["flow"],
            "VLESS flow must be absent, xtls-rprx-vision, or xtls-rprx-vision-udp443; aliases must agree",
        );
        error.category = category;
        error
    };
    let flow = optional_text(query.values("flow").map(Some))
        .map_err(|_| flow_error(ErrorCategory::Parse))?;
    config.flow = optional_flow(flow)
        .map_err(|_| flow_error(ErrorCategory::Validation))?
        .map(str::to_string);
    // Shadowrocket's exporter maps 1 to retired XTLS Direct and 2 to Vision.
    if let Some(xtls) = query.get("xtls") {
        let flow = match xtls.as_str() {
            "0" => None,
            "2" => Some("xtls-rprx-vision"),
            _ => {
                return Err(invalid(
                    &["flow"],
                    "VLESS xtls must be 0 (disabled) or 2 (Vision)",
                ));
            }
        };
        if config.flow.is_some() && config.flow.as_deref() != flow
            || flow.is_some() && !config.tls.enabled
        {
            return Err(flow_error(ErrorCategory::Parse));
        }
        config.flow = flow.map(str::to_string);
    }
    config.encryption = query
        .get("encryption")
        .filter(|value| !value.trim().is_empty())
        .cloned();
    Ok(())
}
