//! Normalize sing-box outbounds into the shared Clash-shaped vocabulary.

use honk_config::types::NodeProtocol;
use serde_yaml::{Mapping, Value};

use super::{NodeResult, move_strings, put, take_optional_string};

#[derive(Clone, Copy, PartialEq, Eq)]
enum PacketNetwork {
    Both,
    TcpOnly,
}

pub(super) fn normalize(value: Value) -> NodeResult {
    let Value::Mapping(mut source) = value else {
        return Err("sing-box outbound must be an object");
    };
    let Some(Value::String(kind)) = source.remove("type") else {
        return Err("sing-box outbound type is missing or invalid");
    };
    let protocol = match kind.as_str() {
        "shadowsocks" | "ss" => NodeProtocol::SS,
        "socks" | "socks5" => NodeProtocol::Socks5,
        "vmess" => NodeProtocol::VMess,
        "vless" => NodeProtocol::VLess,
        "trojan" => NodeProtocol::Trojan,
        "hysteria2" | "hy2" => NodeProtocol::Hysteria2,
        "tuic" => NodeProtocol::Tuic,
        "juicity" => NodeProtocol::Juicity,
        "anytls" => NodeProtocol::AnyTLS,
        "selector" | "urltest" | "direct" | "block" | "dns" => return Ok(None),
        _ => return Ok(None),
    };
    if source.remove("detour").is_some_and(|value| active(&value)) {
        return Err("sing-box detour chaining is unsupported");
    }

    let mut proxy = Mapping::new();
    put(&mut proxy, "type", Value::String(protocol.as_str().into()));
    move_strings(
        &mut source,
        &mut proxy,
        &[("tag", "name"), ("server", "server")],
    )?;
    let hopping_port = if protocol == NodeProtocol::Hysteria2 {
        normalize_server_ports(&mut source, &mut proxy)?
    } else {
        None
    };
    match (source.remove("server_port"), hopping_port) {
        (Some(port), _) if matches!(port.as_u64(), Some(1..=65535)) => {
            put(&mut proxy, "port", port);
        }
        (Some(Value::Null) | None, Some(port)) => {
            put(&mut proxy, "port", Value::Number(port.into()));
        }
        (Some(Value::Null) | None, None) => {}
        _ => return Err("sing-box outbound port must be an integer"),
    }

    match protocol {
        NodeProtocol::SS => normalize_shadowsocks(source, proxy),
        NodeProtocol::Socks5 => normalize_socks5(source, proxy),
        NodeProtocol::VMess => normalize_vmess(source, proxy),
        NodeProtocol::VLess => normalize_vless(source, proxy),
        NodeProtocol::Trojan => normalize_trojan(source, proxy),
        NodeProtocol::Hysteria2 => normalize_hysteria2(source, proxy),
        NodeProtocol::Tuic => normalize_tuic(source, proxy),
        NodeProtocol::Juicity => normalize_juicity(source, proxy),
        NodeProtocol::AnyTLS => normalize_anytls(source, proxy),
        NodeProtocol::Direct | NodeProtocol::Block => unreachable!(),
    }
    .map(Some)
}

fn normalize_shadowsocks(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_strings(
        &mut source,
        &mut proxy,
        &[
            ("method", "cipher"),
            ("password", "password"),
            ("plugin", "plugin"),
            ("plugin_opts", "plugin-opts"),
        ],
    )?;
    reject_packet_network(&mut source)?;
    reject_enabled(
        &mut source,
        "udp_over_tcp",
        "sing-box Shadowsocks UoT is unsupported",
    )?;
    reject_enabled(
        &mut source,
        "multiplex",
        "sing-box Shadowsocks multiplex is unsupported",
    )?;
    Ok(proxy)
}

fn normalize_socks5(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    if let Some(version) = source.remove("version") {
        let is_v5 =
            matches!(&version, Value::String(value) if value == "5") || version.as_u64() == Some(5);
        if !is_v5 {
            return Err("only SOCKS5 sing-box outbounds are supported");
        }
    }
    move_strings(
        &mut source,
        &mut proxy,
        &[("username", "username"), ("password", "password")],
    )?;
    reject_packet_network(&mut source)?;
    reject_enabled(
        &mut source,
        "udp_over_tcp",
        "sing-box SOCKS UoT is unsupported",
    )?;
    Ok(proxy)
}

fn normalize_vmess(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_strings(&mut source, &mut proxy, &[("uuid", "uuid")])?;
    if let Some(security) = source.remove("security") {
        let Value::String(value) = &security else {
            return Err("sing-box VMess security must be a string");
        };
        if !matches!(value.as_str(), "auto" | "aes-128-gcm") {
            return Err("unsupported sing-box VMess security");
        }
        put(&mut proxy, "cipher", security);
    }
    if source
        .remove("alter_id")
        .is_some_and(|value| !matches!(value, Value::Null) && value.as_u64() != Some(0))
    {
        return Err("legacy sing-box VMess alter IDs are unsupported");
    }
    for (key, error) in [
        (
            "global_padding",
            "sing-box VMess global padding is unsupported",
        ),
        (
            "authenticated_length",
            "sing-box VMess authenticated length is unsupported",
        ),
    ] {
        if source.remove(key).is_some_and(|value| active(&value)) {
            return Err(error);
        }
    }
    reject_active_key(
        &mut source,
        "packet_encoding",
        "sing-box VMess packet encoding is unsupported",
    )?;
    normalize_packet_network(&mut source, &mut proxy)?;
    reject_enabled(
        &mut source,
        "multiplex",
        "sing-box VMess multiplex is unsupported",
    )?;
    reject_enabled(
        &mut source,
        "udp_over_tcp",
        "sing-box VMess UoT is unsupported",
    )?;
    normalize_transport(&mut source, &mut proxy)?;
    normalize_tls(&mut source, &mut proxy, NodeProtocol::VMess)?;
    Ok(proxy)
}

fn normalize_vless(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_strings(
        &mut source,
        &mut proxy,
        &[("uuid", "uuid"), ("flow", "flow")],
    )?;
    let network = normalize_packet_network(&mut source, &mut proxy)?;
    let packet_encoding = source.remove("packet_encoding");
    let multiplex = normalize_vless_multiplex(&mut source, &mut proxy)?;
    let uot = normalize_vless_uot(&mut source, &mut proxy)?;
    let packet_encoding = match packet_encoding {
        None | Some(Value::Null) if network == PacketNetwork::Both && !multiplex && !uot => "xudp",
        None | Some(Value::Null) => "",
        Some(Value::String(value)) if matches!(value.as_str(), "" | "xudp") => {
            if value.is_empty() && network == PacketNetwork::Both && !multiplex && !uot {
                return Err("native sing-box VLESS UDP is unsupported");
            }
            if network == PacketNetwork::TcpOnly || multiplex || uot || value.is_empty() {
                ""
            } else {
                "xudp"
            }
        }
        Some(Value::String(_)) => return Err("unsupported sing-box VLESS packet encoding"),
        Some(_) => return Err("sing-box VLESS packet encoding must be a string"),
    };
    put(
        &mut proxy,
        "packet-encoding",
        Value::String(packet_encoding.into()),
    );
    normalize_transport(&mut source, &mut proxy)?;
    normalize_tls(&mut source, &mut proxy, NodeProtocol::VLess)?;
    Ok(proxy)
}

fn normalize_trojan(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_strings(&mut source, &mut proxy, &[("password", "password")])?;
    normalize_packet_network(&mut source, &mut proxy)?;
    reject_enabled(
        &mut source,
        "multiplex",
        "sing-box Trojan multiplex is unsupported",
    )?;
    reject_enabled(
        &mut source,
        "udp_over_tcp",
        "sing-box Trojan UoT is unsupported",
    )?;
    normalize_transport(&mut source, &mut proxy)?;
    normalize_tls(&mut source, &mut proxy, NodeProtocol::Trojan)?;
    Ok(proxy)
}

fn normalize_hysteria2(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_strings(&mut source, &mut proxy, &[("password", "password")])?;
    reject_packet_network(&mut source)?;
    if source.remove("realm").is_some_and(|value| active(&value)) {
        return Err("sing-box Hysteria2 realm routing is unsupported");
    }
    if source
        .remove("hop_interval_max")
        .is_some_and(|value| active(&value))
    {
        return Err("sing-box randomized Hysteria2 hop intervals are unsupported");
    }
    for (source_key, target_key) in [
        ("up_mbps", "up"),
        ("down_mbps", "down"),
        ("hop_interval", "hop-interval"),
    ] {
        if let Some(value) = source.remove(source_key).filter(active) {
            put(&mut proxy, target_key, value);
        }
    }
    normalize_hysteria2_obfs(&mut source, &mut proxy)?;
    normalize_quic_fields(&mut source, &mut proxy)?;
    normalize_tls(&mut source, &mut proxy, NodeProtocol::Hysteria2)?;
    Ok(proxy)
}

fn normalize_tuic(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    if source.remove("token").is_some_and(|value| active(&value)) {
        return Err("legacy TUIC tokens are unsupported");
    }
    move_strings(
        &mut source,
        &mut proxy,
        &[("uuid", "uuid"), ("password", "password")],
    )?;
    if let Some(mode) = source.remove("udp_relay_mode")
        && !matches!(&mode, Value::String(value) if value.is_empty() || value == "native")
    {
        return Err("unsupported sing-box TUIC UDP relay mode");
    }
    if source
        .remove("udp_over_stream")
        .is_some_and(|value| active(&value))
    {
        return Err("forced sing-box TUIC UDP-over-stream is unsupported");
    }
    reject_packet_network(&mut source)?;
    if let Some(congestion) = take_optional_string(&mut source, "congestion_control")? {
        if !matches!(congestion.as_str(), "" | "cubic" | "new_reno" | "bbr") {
            return Err("unsupported sing-box TUIC congestion control");
        }
        if !congestion.trim().is_empty() {
            put(&mut proxy, "congestion-control", Value::String(congestion));
        }
    }
    normalize_quic_fields(&mut source, &mut proxy)?;
    normalize_tls(&mut source, &mut proxy, NodeProtocol::Tuic)?;
    Ok(proxy)
}

fn normalize_juicity(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_strings(
        &mut source,
        &mut proxy,
        &[("uuid", "uuid"), ("password", "password")],
    )?;
    reject_packet_network(&mut source)?;
    normalize_quic_fields(&mut source, &mut proxy)?;
    normalize_tls(&mut source, &mut proxy, NodeProtocol::Juicity)?;
    Ok(proxy)
}

fn normalize_anytls(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_strings(&mut source, &mut proxy, &[("password", "password")])?;
    normalize_packet_network(&mut source, &mut proxy)?;
    for (source_key, target_key) in [
        ("min_idle_session", "min-idle-session"),
        ("idle_session_check_interval", "idle-session-check-interval"),
        ("idle_session_timeout", "idle-session-timeout"),
    ] {
        if let Some(value) = source.remove(source_key).filter(active) {
            put(&mut proxy, target_key, value);
        }
    }
    if source
        .remove("client_metadata")
        .is_some_and(|value| active(&value))
    {
        return Err("sing-box AnyTLS client metadata is unsupported");
    }
    reject_enabled(
        &mut source,
        "multiplex",
        "sing-box AnyTLS multiplex settings are unsupported",
    )?;
    normalize_tls(&mut source, &mut proxy, NodeProtocol::AnyTLS)?;
    Ok(proxy)
}

fn normalize_packet_network(
    source: &mut Mapping,
    proxy: &mut Mapping,
) -> Result<PacketNetwork, &'static str> {
    let Some(network) = source.remove("network") else {
        return Ok(PacketNetwork::Both);
    };
    let Value::String(network) = network else {
        return Err("sing-box packet network must be a string");
    };
    match network.as_str() {
        "" => Ok(PacketNetwork::Both),
        "tcp" => {
            put(proxy, "udp", Value::Bool(false));
            Ok(PacketNetwork::TcpOnly)
        }
        "udp" => Err("UDP-only sing-box packet capability is unsupported"),
        _ => Err("unsupported sing-box packet network"),
    }
}

fn reject_packet_network(source: &mut Mapping) -> Result<(), &'static str> {
    let Some(network) = source.remove("network") else {
        return Ok(());
    };
    if matches!(&network, Value::String(value) if value.is_empty()) {
        return Ok(());
    }
    Err("sing-box packet network restriction is unsupported for this protocol")
}

fn normalize_vless_multiplex(
    source: &mut Mapping,
    proxy: &mut Mapping,
) -> Result<bool, &'static str> {
    let Some(value) = source.remove("multiplex") else {
        return Ok(false);
    };
    if matches!(value, Value::Null) {
        return Ok(false);
    }
    let Value::Mapping(mut multiplex) = value else {
        return Err("sing-box VLESS multiplex settings must be an object");
    };
    if !take_bool(&mut multiplex, "enabled")?.unwrap_or(false) {
        return Ok(false);
    }
    match multiplex.remove("protocol") {
        None => put(&mut multiplex, "protocol", Value::String("h2mux".into())),
        Some(Value::String(protocol)) if protocol.is_empty() || protocol == "h2mux" => {
            put(&mut multiplex, "protocol", Value::String("h2mux".into()))
        }
        Some(Value::String(_)) => return Err("unsupported sing-box VLESS multiplex protocol"),
        Some(_) => return Err("sing-box VLESS multiplex protocol must be a string"),
    }
    reject_unknown_active(
        &multiplex,
        &[
            "protocol",
            "padding",
            "brutal",
            "max_connections",
            "min_streams",
            "max_streams",
        ],
        "unsupported sing-box VLESS multiplex setting",
    )?;
    put(&mut multiplex, "enabled", Value::Bool(true));
    put(proxy, "multiplex", Value::Mapping(multiplex));
    Ok(true)
}

fn normalize_vless_uot(source: &mut Mapping, proxy: &mut Mapping) -> Result<bool, &'static str> {
    let Some(value) = source.remove("udp_over_tcp") else {
        return Ok(false);
    };
    let mut options = match value {
        Value::Bool(false) | Value::Null => return Ok(false),
        Value::Bool(true) => Mapping::new(),
        Value::Mapping(mut options) => {
            if !take_bool(&mut options, "enabled")?.unwrap_or(false) {
                return Ok(false);
            }
            options
        }
        _ => return Err("sing-box VLESS UoT settings must be boolean or an object"),
    };
    match options.remove("version") {
        None => put(&mut options, "version", Value::Number(2.into())),
        Some(version) if version.as_u64() == Some(2) => put(&mut options, "version", version),
        Some(_) => return Err("only sing-box UoT version 2 is supported"),
    }
    reject_unknown_active(
        &options,
        &["version"],
        "unsupported sing-box VLESS UoT setting",
    )?;
    put(&mut options, "enabled", Value::Bool(true));
    put(proxy, "udp-over-tcp", Value::Mapping(options));
    Ok(true)
}

fn normalize_transport(source: &mut Mapping, proxy: &mut Mapping) -> Result<(), &'static str> {
    let Some(value) = source.remove("transport") else {
        return Ok(());
    };
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let Value::Mapping(mut transport) = value else {
        return Err("sing-box transport settings must be an object");
    };
    let kind = match transport.remove("type") {
        Some(Value::String(kind)) => kind,
        Some(_) => return Err("sing-box transport type must be a string"),
        None if transport.values().all(|value| !active(value)) => return Ok(()),
        None => return Err("sing-box transport type is missing"),
    };
    match kind.as_str() {
        "" if transport.values().all(|value| !active(value)) => Ok(()),
        "" => Err("sing-box transport type is missing"),
        "ws" => normalize_ws_transport(transport, proxy),
        "grpc" => normalize_grpc_transport(transport, proxy),
        _ => Err("unsupported sing-box stream transport"),
    }
}

fn normalize_ws_transport(mut transport: Mapping, proxy: &mut Mapping) -> Result<(), &'static str> {
    let mut options = Mapping::new();
    move_strings(&mut transport, &mut options, &[("path", "path")])?;
    if let Some(headers) = transport.remove("headers") {
        let Value::Mapping(headers) = headers else {
            return Err("sing-box WebSocket headers must be an object");
        };
        let mut normalized = Mapping::new();
        for (key, value) in headers {
            let Some(key) = key.as_str() else {
                return Err("sing-box WebSocket header names must be strings");
            };
            if key.eq_ignore_ascii_case("host") {
                if !value.is_string() {
                    return Err("sing-box WebSocket Host header must be a string");
                }
                if normalized
                    .insert(Value::String("Host".into()), value)
                    .is_some()
                {
                    return Err("duplicate sing-box WebSocket Host headers");
                }
            } else if active(&value) {
                return Err("unsupported sing-box WebSocket header");
            }
        }
        if !normalized.is_empty() {
            put(&mut options, "headers", Value::Mapping(normalized));
        }
    }
    reject_active_remainder(&transport, "unsupported sing-box WebSocket settings")?;
    put(proxy, "network", Value::String("ws".into()));
    if !options.is_empty() {
        put(proxy, "ws-opts", Value::Mapping(options));
    }
    Ok(())
}

fn normalize_grpc_transport(
    mut transport: Mapping,
    proxy: &mut Mapping,
) -> Result<(), &'static str> {
    let mut options = Mapping::new();
    let service = take_optional_string(&mut transport, "service_name")?.unwrap_or_default();
    put(&mut options, "grpc-service-name", Value::String(service));
    reject_active_remainder(&transport, "unsupported sing-box gRPC settings")?;
    put(proxy, "network", Value::String("grpc".into()));
    put(proxy, "grpc-opts", Value::Mapping(options));
    Ok(())
}

fn normalize_tls(
    source: &mut Mapping,
    proxy: &mut Mapping,
    protocol: NodeProtocol,
) -> Result<(), &'static str> {
    let Some(value) = source.remove("tls") else {
        put(proxy, "tls", Value::Bool(false));
        return Ok(());
    };
    let Value::Mapping(mut tls) = value else {
        return Err("sing-box TLS settings must be an object");
    };
    let enabled = take_bool(&mut tls, "enabled")?.unwrap_or(false);
    let server_name = take_optional_string(&mut tls, "server_name")?;
    let insecure = take_bool(&mut tls, "insecure")?.unwrap_or(false);
    let reality = tls.remove("reality");
    let alpn = tls.remove("alpn");
    if let Some(engine) = take_optional_string(&mut tls, "engine")?
        && !matches!(engine.as_str(), "" | "go")
    {
        return Err("unsupported sing-box TLS engine");
    }
    // uTLS changes the ClientHello fingerprint, not endpoint authentication or
    // the negotiated proxy protocol. honk selects fingerprints process-wide.
    tls.remove("utls");
    if !enabled
        && (server_name
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty())
            || insecure
            || reality.as_ref().is_some_and(active)
            || alpn.as_ref().is_some_and(active))
    {
        return Err("disabled sing-box TLS has active TLS-only settings");
    }
    reject_active_remainder(&tls, "unsupported sing-box TLS settings")?;

    put(proxy, "tls", Value::Bool(enabled));
    if let Some(server_name) = server_name.filter(|value| !value.trim().is_empty()) {
        put(proxy, "servername", Value::String(server_name));
    }
    if insecure {
        put(proxy, "skip-cert-verify", Value::Bool(true));
    }
    if let Some(reality) = reality {
        normalize_reality(reality, proxy)?;
    }
    if let Some(alpn) = alpn.filter(active) {
        validate_alpn(&alpn)?;
        let fixed_h3 = matches!(&alpn, Value::String(value) if value == "h3")
            || matches!(&alpn, Value::Sequence(values) if values.len() == 1 && values[0].as_str() == Some("h3"));
        if protocol != NodeProtocol::Tuic
            && !(matches!(protocol, NodeProtocol::Hysteria2 | NodeProtocol::Juicity) && fixed_h3)
        {
            return Err("TLS ALPN is unsupported for this sing-box protocol");
        }
        put(proxy, "alpn", alpn);
    }
    Ok(())
}

fn normalize_reality(value: Value, proxy: &mut Mapping) -> Result<(), &'static str> {
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let Value::Mapping(mut reality) = value else {
        return Err("sing-box REALITY settings must be an object");
    };
    if !take_bool(&mut reality, "enabled")?.unwrap_or(false) {
        return Ok(());
    }
    let Some(public_key) =
        take_optional_string(&mut reality, "public_key")?.filter(|value| !value.trim().is_empty())
    else {
        return Err("sing-box REALITY public key is missing");
    };
    let short_id = take_optional_string(&mut reality, "short_id")?;
    reject_active_remainder(&reality, "unsupported sing-box REALITY settings")?;
    let mut options = Mapping::new();
    put(&mut options, "public-key", Value::String(public_key));
    if let Some(short_id) = short_id {
        put(&mut options, "short-id", Value::String(short_id));
    }
    put(proxy, "reality-opts", Value::Mapping(options));
    Ok(())
}

fn validate_alpn(value: &Value) -> Result<(), &'static str> {
    match value {
        Value::String(_) => Ok(()),
        Value::Sequence(values) if values.iter().all(Value::is_string) => Ok(()),
        _ => Err("sing-box TLS ALPN must be a string or string array"),
    }
}

fn normalize_hysteria2_obfs(source: &mut Mapping, proxy: &mut Mapping) -> Result<(), &'static str> {
    let Some(value) = source.remove("obfs") else {
        return Ok(());
    };
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let Value::Mapping(mut obfs) = value else {
        return Err("sing-box Hysteria2 obfs settings must be an object");
    };
    let Some(obfs_type) =
        take_optional_string(&mut obfs, "type")?.filter(|value| !value.trim().is_empty())
    else {
        if obfs.values().any(active) {
            return Err("sing-box Hysteria2 obfs type is missing");
        }
        return Ok(());
    };
    if obfs_type != "salamander" {
        return Err("unsupported sing-box Hysteria2 obfs type");
    }
    let Some(password) =
        take_optional_string(&mut obfs, "password")?.filter(|value| !value.trim().is_empty())
    else {
        return Err("sing-box Hysteria2 obfs password is missing");
    };
    reject_active_remainder(&obfs, "unsupported sing-box Hysteria2 obfs settings")?;
    put(proxy, "obfs", Value::String("salamander".into()));
    put(proxy, "obfs-password", Value::String(password));
    Ok(())
}

fn normalize_server_ports(
    source: &mut Mapping,
    proxy: &mut Mapping,
) -> Result<Option<u16>, &'static str> {
    let Some(value) = source.remove("server_ports") else {
        return Ok(None);
    };
    let values = match value {
        Value::Null => return Ok(None),
        Value::String(value) => vec![value],
        Value::Sequence(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(value) => Ok(value),
                _ => Err("sing-box Hysteria2 server ports must be strings"),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("sing-box Hysteria2 server ports must be a string array"),
    };
    if values.is_empty() || (values.len() == 1 && values[0].trim().is_empty()) {
        return Ok(None);
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err("sing-box Hysteria2 server ports must not contain empty entries");
    }
    let ports = values
        .into_iter()
        .map(|value| value.replace(':', "-"))
        .collect::<Vec<_>>()
        .join(",");
    let mut first_port = None;
    for range in ports.split(',') {
        let (start, end) = range
            .split_once('-')
            .map_or((range, range), |(start, end)| (start, end));
        let start = start.trim().parse::<u16>().ok().filter(|port| *port > 0);
        let end = end.trim().parse::<u16>().ok().filter(|port| *port > 0);
        let (Some(start), Some(end)) = (start, end) else {
            return Err("sing-box Hysteria2 server ports are invalid");
        };
        if start > end {
            return Err("sing-box Hysteria2 server ports are invalid");
        }
        first_port.get_or_insert(start);
    }
    put(proxy, "ports", Value::String(ports));
    Ok(first_port)
}

fn normalize_quic_fields(source: &mut Mapping, proxy: &mut Mapping) -> Result<(), &'static str> {
    for (keys, target_key, conflict) in [
        (
            [
                "initial_stream_receive_window",
                "init_stream_receive_window",
            ],
            "initial-stream-receive-window",
            "conflicting sing-box QUIC stream window fields",
        ),
        (
            [
                "initial_connection_receive_window",
                "initial_conn_receive_window",
            ],
            "initial-conn-receive-window",
            "conflicting sing-box QUIC connection window fields",
        ),
    ] {
        if let Some(value) = take_alias(source, &keys, conflict)?.filter(active) {
            put(proxy, target_key, value);
        }
    }
    if let Some(mtu) = source.remove("initial_packet_size").filter(active) {
        put(proxy, "mtu", mtu);
    }
    if let Some(disable_mtu) = take_alias(
        source,
        &["disable_path_mtu_discovery", "disable_mtu_discovery"],
        "conflicting sing-box QUIC MTU discovery fields",
    )? {
        let Value::Bool(disabled) = disable_mtu else {
            return Err("sing-box QUIC MTU discovery setting must be boolean");
        };
        if disabled {
            put(proxy, "disable-mtu-discovery", Value::Bool(true));
        }
    }
    for key in [
        "stream_receive_window",
        "connection_receive_window",
        "max_concurrent_streams",
    ] {
        reject_active_key(
            source,
            key,
            "unsupported sing-box QUIC flow-control setting",
        )?;
    }
    Ok(())
}

fn reject_enabled(
    source: &mut Mapping,
    key: &str,
    error: &'static str,
) -> Result<(), &'static str> {
    let Some(value) = source.remove(key) else {
        return Ok(());
    };
    let enabled = match value {
        Value::Null | Value::Bool(false) => false,
        Value::Bool(true) => true,
        Value::Mapping(mut options) => take_bool(&mut options, "enabled")?.unwrap_or(false),
        _ => return Err("sing-box feature settings must be boolean or an object"),
    };
    if enabled { Err(error) } else { Ok(()) }
}

fn reject_active_key(
    mapping: &mut Mapping,
    key: &str,
    error: &'static str,
) -> Result<(), &'static str> {
    if mapping.remove(key).is_some_and(|value| active(&value)) {
        Err(error)
    } else {
        Ok(())
    }
}

fn reject_active_remainder(mapping: &Mapping, error: &'static str) -> Result<(), &'static str> {
    if mapping.values().any(active) {
        Err(error)
    } else {
        Ok(())
    }
}

fn reject_unknown_active(
    mapping: &Mapping,
    allowed: &[&str],
    error: &'static str,
) -> Result<(), &'static str> {
    if mapping
        .iter()
        .any(|(key, value)| active(value) && key.as_str().is_none_or(|key| !allowed.contains(&key)))
    {
        Err(error)
    } else {
        Ok(())
    }
}

fn active(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.trim().is_empty(),
        Value::Sequence(value) => !value.is_empty(),
        Value::Mapping(value) => value.values().any(active),
        Value::Tagged(value) => active(&value.value),
    }
}

fn take_bool(mapping: &mut Mapping, key: &str) -> Result<Option<bool>, &'static str> {
    match mapping.remove(key) {
        Some(Value::Bool(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        Some(_) => Err("sing-box boolean setting has an invalid type"),
        None => Ok(None),
    }
}

fn take_alias(
    source: &mut Mapping,
    keys: &[&str],
    conflict: &'static str,
) -> Result<Option<Value>, &'static str> {
    let mut value = None;
    for key in keys {
        if let Some(found) = source.remove(*key) {
            if value.is_some() {
                return Err(conflict);
            }
            value = Some(found);
        }
    }
    Ok(value)
}
