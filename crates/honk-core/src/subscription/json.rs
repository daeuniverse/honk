//! SIP008 and sing-box node imports normalized through the common Clash builder.

use honk_config::node::Node;
use serde_yaml::{Mapping, Value};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Shadowsocks,
    Socks5,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    Tuic,
    Juicity,
    AnyTls,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PacketNetwork {
    Both,
    TcpOnly,
}

type NodeResult = Result<Option<Mapping>, &'static str>;

pub(super) fn parse_json_subscription(
    value: Value,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    match value {
        Value::Sequence(servers) => parse_entries(servers, subscription_id, normalize_sip008),
        Value::Mapping(mut root) => {
            let outbounds = take(&mut root, "outbounds");
            let servers = take(&mut root, "servers");
            match (outbounds, servers) {
                (Some(_), Some(_)) => anyhow::bail!("ambiguous JSON subscription wrapper"),
                (Some(Value::Sequence(outbounds)), None) => {
                    parse_entries(outbounds, subscription_id, normalize_sing_box)
                }
                (Some(_), None) => anyhow::bail!("sing-box 'outbounds' must be an array"),
                (None, Some(Value::Sequence(servers))) => {
                    if let Some(version) = take(&mut root, "version")
                        && !matches!(version.as_u64(), Some(1 | 2))
                    {
                        anyhow::bail!("unsupported SIP008 version");
                    }
                    parse_entries(servers, subscription_id, normalize_sip008)
                }
                (None, Some(_)) => anyhow::bail!("SIP008 'servers' must be an array"),
                (None, None) => anyhow::bail!("unsupported JSON subscription wrapper"),
            }
        }
        _ => anyhow::bail!("JSON subscription root must be an object or array"),
    }
}

fn parse_entries(
    entries: Vec<Value>,
    subscription_id: Option<uuid::Uuid>,
    normalize: fn(Value) -> NodeResult,
) -> anyhow::Result<Vec<Node>> {
    let mut proxies = Vec::with_capacity(entries.len());
    let mut first_error = None;
    for entry in entries {
        match normalize(entry) {
            Ok(Some(proxy)) => proxies.push(Value::Mapping(proxy)),
            Ok(None) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        };
    }
    if proxies.is_empty()
        && let Some(error) = first_error
    {
        anyhow::bail!(error);
    }
    super::parse_clash_proxies(&proxies, subscription_id)
}

fn normalize_sip008(value: Value) -> NodeResult {
    let Value::Mapping(mut source) = value else {
        return Err("SIP008 server must be an object");
    };
    let mut proxy = Mapping::new();
    put(&mut proxy, "type", Value::String("ss".into()));
    move_required_string(
        &mut source,
        &mut proxy,
        "server",
        "server",
        "SIP008 server address is missing or invalid",
    )?;
    move_required_port(
        &mut source,
        &mut proxy,
        "server_port",
        "port",
        "SIP008 server port is missing or invalid",
    )?;
    move_required_string(
        &mut source,
        &mut proxy,
        "method",
        "cipher",
        "SIP008 method is missing or invalid",
    )?;
    move_required_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "SIP008 password is missing or invalid",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "remarks",
        "name",
        "SIP008 remarks must be a string",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "plugin",
        "plugin",
        "SIP008 plugin must be a string",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "plugin_opts",
        "plugin-opts",
        "SIP008 plugin options must be a string",
    )?;
    Ok(Some(proxy))
}

fn normalize_sing_box(value: Value) -> NodeResult {
    let Value::Mapping(mut source) = value else {
        return Err("sing-box outbound must be an object");
    };
    let Some(Value::String(kind)) = take(&mut source, "type") else {
        return Err("sing-box outbound type is missing or invalid");
    };
    let protocol = match kind.as_str() {
        "shadowsocks" | "ss" => Protocol::Shadowsocks,
        "socks" | "socks5" => Protocol::Socks5,
        "vmess" => Protocol::Vmess,
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        "hysteria2" | "hy2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        "juicity" => Protocol::Juicity,
        "anytls" => Protocol::AnyTls,
        "selector" | "urltest" | "direct" | "block" | "dns" => return Ok(None),
        _ => return Ok(None),
    };
    if take(&mut source, "detour").is_some_and(|value| active(&value)) {
        return Err("sing-box detour chaining is unsupported");
    }

    let mut proxy = Mapping::new();
    put(
        &mut proxy,
        "type",
        Value::String(
            match protocol {
                Protocol::Shadowsocks => "ss",
                Protocol::Socks5 => "socks5",
                Protocol::Vmess => "vmess",
                Protocol::Vless => "vless",
                Protocol::Trojan => "trojan",
                Protocol::Hysteria2 => "hysteria2",
                Protocol::Tuic => "tuic",
                Protocol::Juicity => "juicity",
                Protocol::AnyTls => "anytls",
            }
            .into(),
        ),
    );
    move_optional_string(
        &mut source,
        &mut proxy,
        "tag",
        "name",
        "sing-box outbound tag must be a string",
    )?;
    move_required_string(
        &mut source,
        &mut proxy,
        "server",
        "server",
        "sing-box outbound server is missing or invalid",
    )?;
    let hopping_port = if protocol == Protocol::Hysteria2 {
        normalize_server_ports(&mut source, &mut proxy)?
    } else {
        None
    };
    match (take(&mut source, "server_port"), hopping_port) {
        (Some(port), _) if matches!(port.as_u64(), Some(1..=65535)) => {
            put(&mut proxy, "port", port);
        }
        (Some(Value::Null) | None, Some(port)) => {
            put(&mut proxy, "port", Value::Number(port.into()));
        }
        _ => return Err("sing-box outbound port is missing or invalid"),
    }

    match protocol {
        Protocol::Shadowsocks => normalize_shadowsocks(source, proxy),
        Protocol::Socks5 => normalize_socks5(source, proxy),
        Protocol::Vmess => normalize_vmess(source, proxy),
        Protocol::Vless => normalize_vless(source, proxy),
        Protocol::Trojan => normalize_trojan(source, proxy),
        Protocol::Hysteria2 => normalize_hysteria2(source, proxy),
        Protocol::Tuic => normalize_tuic(source, proxy),
        Protocol::Juicity => normalize_juicity(source, proxy),
        Protocol::AnyTls => normalize_anytls(source, proxy),
    }
    .map(Some)
}

fn normalize_shadowsocks(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_required_string(
        &mut source,
        &mut proxy,
        "method",
        "cipher",
        "sing-box Shadowsocks method is missing or invalid",
    )?;
    move_required_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "sing-box Shadowsocks password is missing or invalid",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "plugin",
        "plugin",
        "sing-box Shadowsocks plugin must be a string",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "plugin_opts",
        "plugin-opts",
        "sing-box Shadowsocks plugin options must be a string",
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
    if let Some(version) = take(&mut source, "version") {
        let is_v5 =
            matches!(&version, Value::String(value) if value == "5") || version.as_u64() == Some(5);
        if !is_v5 {
            return Err("only SOCKS5 sing-box outbounds are supported");
        }
    }
    move_optional_string(
        &mut source,
        &mut proxy,
        "username",
        "username",
        "sing-box SOCKS username must be a string",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "sing-box SOCKS password must be a string",
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
    move_required_string(
        &mut source,
        &mut proxy,
        "uuid",
        "uuid",
        "sing-box VMess UUID is missing or invalid",
    )?;
    if let Some(security) = take(&mut source, "security") {
        let Value::String(value) = &security else {
            return Err("sing-box VMess security must be a string");
        };
        if !matches!(value.as_str(), "auto" | "aes-128-gcm") {
            return Err("unsupported sing-box VMess security");
        }
        put(&mut proxy, "cipher", security);
    }
    if take(&mut source, "alter_id")
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
        if take(&mut source, key).is_some_and(|value| active(&value)) {
            return Err(error);
        }
    }
    reject_packet_encoding(&mut source, "sing-box VMess packet encoding is unsupported")?;
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
    normalize_tls(&mut source, &mut proxy, Protocol::Vmess, false)?;
    Ok(proxy)
}

fn normalize_vless(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_required_string(
        &mut source,
        &mut proxy,
        "uuid",
        "uuid",
        "sing-box VLESS UUID is missing or invalid",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "flow",
        "flow",
        "sing-box VLESS flow must be a string",
    )?;
    let network = normalize_packet_network(&mut source, &mut proxy)?;
    let packet_encoding = take(&mut source, "packet_encoding");
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
    normalize_tls(&mut source, &mut proxy, Protocol::Vless, false)?;
    Ok(proxy)
}

fn normalize_trojan(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_required_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "sing-box Trojan password is missing or invalid",
    )?;
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
    normalize_tls(&mut source, &mut proxy, Protocol::Trojan, true)?;
    Ok(proxy)
}

fn normalize_hysteria2(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_optional_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "sing-box Hysteria2 password must be a string",
    )?;
    reject_packet_network(&mut source)?;
    if take(&mut source, "realm").is_some_and(|value| active(&value)) {
        return Err("sing-box Hysteria2 realm routing is unsupported");
    }
    if take(&mut source, "hop_interval_max").is_some_and(|value| active(&value)) {
        return Err("sing-box randomized Hysteria2 hop intervals are unsupported");
    }
    move_alias(
        &mut source,
        &mut proxy,
        &["up_mbps"],
        "up",
        "conflicting sing-box Hysteria2 upload bandwidth fields",
    )?;
    move_alias(
        &mut source,
        &mut proxy,
        &["down_mbps"],
        "down",
        "conflicting sing-box Hysteria2 download bandwidth fields",
    )?;
    move_alias(
        &mut source,
        &mut proxy,
        &["hop_interval"],
        "hop-interval",
        "conflicting sing-box Hysteria2 hop interval fields",
    )?;
    normalize_hysteria2_obfs(&mut source, &mut proxy)?;
    normalize_quic_fields(&mut source, &mut proxy, true)?;
    normalize_tls(&mut source, &mut proxy, Protocol::Hysteria2, true)?;
    Ok(proxy)
}

fn normalize_tuic(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    if take(&mut source, "token").is_some_and(|value| active(&value)) {
        return Err("legacy TUIC tokens are unsupported");
    }
    move_required_string(
        &mut source,
        &mut proxy,
        "uuid",
        "uuid",
        "sing-box TUIC UUID is missing or invalid",
    )?;
    move_optional_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "sing-box TUIC password must be a string",
    )?;
    if let Some(mode) = take(&mut source, "udp_relay_mode") {
        if !matches!(mode, Value::String(ref value) if value.is_empty() || value == "native") {
            return Err("unsupported sing-box TUIC UDP relay mode");
        }
    }
    if take(&mut source, "udp_over_stream").is_some_and(|value| active(&value)) {
        return Err("forced sing-box TUIC UDP-over-stream is unsupported");
    }
    reject_packet_network(&mut source)?;
    if let Some(congestion) = take_optional_string(
        &mut source,
        "congestion_control",
        "sing-box TUIC congestion control must be a string",
    )? {
        let Value::String(value) = &congestion else {
            unreachable!();
        };
        if !matches!(value.as_str(), "" | "cubic" | "new_reno" | "bbr") {
            return Err("unsupported sing-box TUIC congestion control");
        }
        if active(&congestion) {
            put(&mut proxy, "congestion-control", congestion);
        }
    }
    normalize_quic_fields(&mut source, &mut proxy, false)?;
    normalize_tls(&mut source, &mut proxy, Protocol::Tuic, true)?;
    Ok(proxy)
}

fn normalize_juicity(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_required_string(
        &mut source,
        &mut proxy,
        "uuid",
        "uuid",
        "sing-box Juicity UUID is missing or invalid",
    )?;
    move_required_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "sing-box Juicity password is missing or invalid",
    )?;
    reject_packet_network(&mut source)?;
    normalize_quic_fields(&mut source, &mut proxy, false)?;
    normalize_tls(&mut source, &mut proxy, Protocol::Juicity, true)?;
    Ok(proxy)
}

fn normalize_anytls(mut source: Mapping, mut proxy: Mapping) -> Result<Mapping, &'static str> {
    move_required_string(
        &mut source,
        &mut proxy,
        "password",
        "password",
        "sing-box AnyTLS password is missing or invalid",
    )?;
    normalize_packet_network(&mut source, &mut proxy)?;
    for (source_key, target_key) in [
        ("min_idle_session", "min-idle-session"),
        ("idle_session_check_interval", "idle-session-check-interval"),
        ("idle_session_timeout", "idle-session-timeout"),
    ] {
        move_alias(
            &mut source,
            &mut proxy,
            &[source_key],
            target_key,
            "conflicting sing-box AnyTLS session settings",
        )?;
    }
    if take(&mut source, "client_metadata").is_some_and(|value| active(&value)) {
        return Err("sing-box AnyTLS client metadata is unsupported");
    }
    reject_enabled(
        &mut source,
        "multiplex",
        "sing-box AnyTLS multiplex settings are unsupported",
    )?;
    normalize_tls(&mut source, &mut proxy, Protocol::AnyTls, true)?;
    Ok(proxy)
}

fn normalize_packet_network(
    source: &mut Mapping,
    proxy: &mut Mapping,
) -> Result<PacketNetwork, &'static str> {
    let Some(network) = take(source, "network") else {
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
    let Some(network) = take(source, "network") else {
        return Ok(());
    };
    if matches!(network, Value::String(ref value) if value.is_empty()) {
        return Ok(());
    }
    Err("sing-box packet network restriction is unsupported for this protocol")
}

fn reject_packet_encoding(source: &mut Mapping, error: &'static str) -> Result<(), &'static str> {
    if take(source, "packet_encoding").is_some_and(|value| active(&value)) {
        return Err(error);
    }
    Ok(())
}

fn normalize_vless_multiplex(
    source: &mut Mapping,
    proxy: &mut Mapping,
) -> Result<bool, &'static str> {
    let Some(value) = take(source, "multiplex") else {
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
    match take(&mut multiplex, "protocol") {
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
    let Some(value) = take(source, "udp_over_tcp") else {
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
    match take(&mut options, "version") {
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
    let Some(value) = take(source, "transport") else {
        return Ok(());
    };
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let Value::Mapping(mut transport) = value else {
        return Err("sing-box transport settings must be an object");
    };
    let kind = match take(&mut transport, "type") {
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
    move_optional_string(
        &mut transport,
        &mut options,
        "path",
        "path",
        "sing-box WebSocket path must be a string",
    )?;
    if let Some(headers) = take(&mut transport, "headers") {
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
    reject_active_key(
        &mut transport,
        "max_early_data",
        "sing-box WebSocket early data is unsupported",
    )?;
    reject_active_key(
        &mut transport,
        "early_data_header_name",
        "sing-box WebSocket early data is unsupported",
    )?;
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
    let service = take_optional_string(
        &mut transport,
        "service_name",
        "sing-box gRPC service name must be a string",
    )?
    .unwrap_or_else(|| Value::String(String::new()));
    put(&mut options, "grpc-service-name", service);
    for key in ["idle_timeout", "ping_timeout", "permit_without_stream"] {
        reject_active_key(
            &mut transport,
            key,
            "sing-box gRPC keepalive settings are unsupported",
        )?;
    }
    reject_active_remainder(&transport, "unsupported sing-box gRPC settings")?;
    put(proxy, "network", Value::String("grpc".into()));
    if !options.is_empty() {
        put(proxy, "grpc-opts", Value::Mapping(options));
    }
    Ok(())
}

fn normalize_tls(
    source: &mut Mapping,
    proxy: &mut Mapping,
    protocol: Protocol,
    required: bool,
) -> Result<(), &'static str> {
    let Some(value) = take(source, "tls") else {
        return if required {
            Err("sing-box outbound requires TLS")
        } else {
            Ok(())
        };
    };
    let Value::Mapping(mut tls) = value else {
        return Err("sing-box TLS settings must be an object");
    };
    let enabled = take_bool(&mut tls, "enabled")?.unwrap_or(false);
    if required && !enabled {
        return Err("sing-box outbound requires enabled TLS");
    }
    let server_name = take_optional_string(
        &mut tls,
        "server_name",
        "sing-box TLS server name must be a string",
    )?;
    let insecure = take_bool(&mut tls, "insecure")?.unwrap_or(false);
    let reality = take(&mut tls, "reality");
    let alpn = take(&mut tls, "alpn");
    if let Some(engine) =
        take_optional_string(&mut tls, "engine", "sing-box TLS engine must be a string")?
    {
        let Value::String(engine) = engine else {
            unreachable!();
        };
        if !matches!(engine.as_str(), "" | "go") {
            return Err("unsupported sing-box TLS engine");
        }
    }
    // uTLS changes the ClientHello fingerprint, not endpoint authentication or
    // the negotiated proxy protocol. honk selects fingerprints process-wide.
    take(&mut tls, "utls");
    if !enabled
        && (server_name.as_ref().is_some_and(active)
            || insecure
            || reality.as_ref().is_some_and(active)
            || alpn.as_ref().is_some_and(active))
    {
        return Err("disabled sing-box TLS has active TLS-only settings");
    }
    reject_active_remainder(&tls, "unsupported sing-box TLS settings")?;

    put(proxy, "tls", Value::Bool(enabled));
    if let Some(server_name) = server_name.filter(active) {
        put(proxy, "servername", server_name);
    }
    if insecure {
        put(proxy, "skip-cert-verify", Value::Bool(true));
    }
    if let Some(reality) = reality {
        normalize_reality(reality, proxy, protocol, enabled)?;
    }
    if let Some(alpn) = alpn.filter(active) {
        validate_alpn(&alpn)?;
        let fixed_h3 = matches!(&alpn, Value::String(value) if value == "h3")
            || matches!(&alpn, Value::Sequence(values) if values.len() == 1 && values[0].as_str() == Some("h3"));
        if protocol != Protocol::Tuic
            && !(matches!(protocol, Protocol::Hysteria2 | Protocol::Juicity) && fixed_h3)
        {
            return Err("TLS ALPN is unsupported for this sing-box protocol");
        }
        put(proxy, "alpn", alpn);
    }
    Ok(())
}

fn normalize_reality(
    value: Value,
    proxy: &mut Mapping,
    protocol: Protocol,
    tls_enabled: bool,
) -> Result<(), &'static str> {
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let Value::Mapping(mut reality) = value else {
        return Err("sing-box REALITY settings must be an object");
    };
    if !take_bool(&mut reality, "enabled")?.unwrap_or(false) {
        return Ok(());
    }
    if !tls_enabled {
        return Err("sing-box REALITY requires TLS");
    }
    if !matches!(
        protocol,
        Protocol::Vmess | Protocol::Vless | Protocol::Trojan
    ) {
        return Err("sing-box REALITY is unsupported for this protocol");
    }
    let Some(public_key) = take_optional_string(
        &mut reality,
        "public_key",
        "sing-box REALITY public key must be a string",
    )?
    .filter(active) else {
        return Err("sing-box REALITY public key is missing");
    };
    let short_id = take_optional_string(
        &mut reality,
        "short_id",
        "sing-box REALITY short ID must be a string",
    )?;
    reject_active_remainder(&reality, "unsupported sing-box REALITY settings")?;
    let mut options = Mapping::new();
    put(&mut options, "public-key", public_key);
    if let Some(short_id) = short_id {
        put(&mut options, "short-id", short_id);
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
    let Some(value) = take(source, "obfs") else {
        return Ok(());
    };
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let Value::Mapping(mut obfs) = value else {
        return Err("sing-box Hysteria2 obfs settings must be an object");
    };
    let obfs_type = take_optional_string(
        &mut obfs,
        "type",
        "sing-box Hysteria2 obfs type must be a string",
    )?;
    let Some(Value::String(obfs_type)) = obfs_type.filter(active) else {
        if obfs.values().any(active) {
            return Err("sing-box Hysteria2 obfs type is missing");
        }
        return Ok(());
    };
    if obfs_type != "salamander" {
        return Err("unsupported sing-box Hysteria2 obfs type");
    }
    let Some(password) = take_optional_string(
        &mut obfs,
        "password",
        "sing-box Hysteria2 obfs password must be a string",
    )?
    .filter(active) else {
        return Err("sing-box Hysteria2 obfs password is missing");
    };
    reject_active_remainder(&obfs, "unsupported sing-box Hysteria2 obfs settings")?;
    put(proxy, "obfs", Value::String("salamander".into()));
    put(proxy, "obfs-password", password);
    Ok(())
}

fn normalize_server_ports(
    source: &mut Mapping,
    proxy: &mut Mapping,
) -> Result<Option<u16>, &'static str> {
    let Some(value) = take(source, "server_ports") else {
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

fn normalize_quic_fields(
    source: &mut Mapping,
    proxy: &mut Mapping,
    supports_mtu_discovery: bool,
) -> Result<(), &'static str> {
    move_alias(
        source,
        proxy,
        &[
            "initial_stream_receive_window",
            "init_stream_receive_window",
        ],
        "initial-stream-receive-window",
        "conflicting sing-box QUIC stream window fields",
    )?;
    move_alias(
        source,
        proxy,
        &[
            "initial_connection_receive_window",
            "initial_conn_receive_window",
        ],
        "initial-conn-receive-window",
        "conflicting sing-box QUIC connection window fields",
    )?;
    if let Some(mtu) = take(source, "initial_packet_size")
        && active(&mtu)
    {
        put(proxy, "mtu", mtu);
    }
    let disable_mtu = take_alias(
        source,
        &["disable_path_mtu_discovery", "disable_mtu_discovery"],
        "conflicting sing-box QUIC MTU discovery fields",
    )?;
    if let Some(disable_mtu) = disable_mtu {
        let Value::Bool(disabled) = disable_mtu else {
            return Err("sing-box QUIC MTU discovery setting must be boolean");
        };
        if disabled && !supports_mtu_discovery {
            return Err("sing-box QUIC MTU discovery setting is unsupported");
        }
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
    let Some(value) = take(source, key) else {
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
    if take(mapping, key).is_some_and(|value| active(&value)) {
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
    if mapping.iter().any(|(key, value)| {
        active(value)
            && key
                .as_str()
                .is_none_or(|key| !allowed.iter().any(|allowed| key == *allowed))
    }) {
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

fn take(mapping: &mut Mapping, key: &str) -> Option<Value> {
    mapping.remove(key)
}

fn put(mapping: &mut Mapping, key: &str, value: Value) {
    mapping.insert(Value::String(key.into()), value);
}

fn take_bool(mapping: &mut Mapping, key: &str) -> Result<Option<bool>, &'static str> {
    match take(mapping, key) {
        Some(Value::Bool(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        Some(_) => Err("sing-box boolean setting has an invalid type"),
        None => Ok(None),
    }
}

fn take_optional_string(
    mapping: &mut Mapping,
    key: &str,
    error: &'static str,
) -> Result<Option<Value>, &'static str> {
    match take(mapping, key) {
        Some(value @ Value::String(_)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        Some(_) => Err(error),
        None => Ok(None),
    }
}

fn move_optional_string(
    source: &mut Mapping,
    target: &mut Mapping,
    source_key: &str,
    target_key: &str,
    error: &'static str,
) -> Result<(), &'static str> {
    if let Some(value) = take_optional_string(source, source_key, error)?
        && active(&value)
    {
        put(target, target_key, value);
    }
    Ok(())
}

fn move_required_string(
    source: &mut Mapping,
    target: &mut Mapping,
    source_key: &str,
    target_key: &str,
    error: &'static str,
) -> Result<(), &'static str> {
    let Some(value) = take_optional_string(source, source_key, error)?.filter(active) else {
        return Err(error);
    };
    put(target, target_key, value);
    Ok(())
}

fn move_required_port(
    source: &mut Mapping,
    target: &mut Mapping,
    source_key: &str,
    target_key: &str,
    error: &'static str,
) -> Result<(), &'static str> {
    let Some(value) = take(source, source_key) else {
        return Err(error);
    };
    if !matches!(value.as_u64(), Some(1..=65535)) {
        return Err(error);
    }
    put(target, target_key, value);
    Ok(())
}

fn take_alias(
    source: &mut Mapping,
    keys: &[&str],
    conflict: &'static str,
) -> Result<Option<Value>, &'static str> {
    let mut value = None;
    for key in keys {
        if let Some(found) = take(source, key) {
            if value.is_some() {
                return Err(conflict);
            }
            value = Some(found);
        }
    }
    Ok(value)
}

fn move_alias(
    source: &mut Mapping,
    target: &mut Mapping,
    keys: &[&str],
    target_key: &str,
    conflict: &'static str,
) -> Result<(), &'static str> {
    if let Some(value) = take_alias(source, keys, conflict)?.filter(active) {
        put(target, target_key, value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use honk_config::node::WireMode;
    use honk_config::types::NodeProtocol;

    use super::*;

    fn json(input: &str) -> Value {
        serde_yaml::from_str(input).unwrap()
    }

    #[test]
    fn sip008_wrappers_and_server_lists_normalize_to_shadowsocks() {
        for input in [
            r#"{"version":1,"servers":[{"id":"00000000-0000-4000-8000-000000000001","remarks":"sip-node","server":"sip.example","server_port":8388,"method":"aes-256-gcm","password":"password","plugin":"","plugin_opts":""}]}"#,
            r#"[{"remarks":"sip-node","server":"sip.example","server_port":8388,"method":"aes-256-gcm","password":"password"}]"#,
            r#"{"version":2,"servers":[{"remarks":"sip-node","server":"sip.example","server_port":8388,"method":"aes-256-gcm","password":"password"}]}"#,
        ] {
            let subscription_id = uuid::Uuid::new_v4();
            let nodes = parse_json_subscription(json(input), Some(subscription_id)).unwrap();
            assert_eq!(nodes.len(), 1);
            let node = &nodes[0];
            assert_eq!(node.protocol(), NodeProtocol::SS);
            assert_eq!(node.name, "sip-node");
            assert_eq!(node.host(), "sip.example");
            assert_eq!(node.port, 8388);
            assert_eq!(node.subscription_id, Some(subscription_id));
            let shadowsocks = node.shadowsocks().unwrap();
            assert_eq!(shadowsocks.encryption.as_deref(), Some("aes-256-gcm"));
            assert_eq!(shadowsocks.password.as_deref(), Some("password"));
            assert_eq!(node.id, node.derive_id());
        }
    }

    #[test]
    fn sing_box_outbounds_preserve_supported_protocol_configuration() {
        let nodes = parse_json_subscription(
            json(
                r#"{
                  "outbounds": [
                    {"type":"selector","tag":"select","outbounds":["ss"]},
                    {"type":"urltest","tag":"auto","outbounds":["ss"]},
                    {"type":"direct","tag":"direct"},
                    {"type":"block","tag":"block"},
                    {"type":"dns","tag":"dns"},
                    {"type":"shadowsocks","tag":"ss","server":"ss.example","server_port":8388,"method":"aes-256-gcm","password":"ss-password"},
                    {"type":"socks","tag":"socks","server":"socks.example","server_port":1080,"version":"5","username":"user","password":"socks-password"},
                    {"type":"vmess","tag":"vmess","server":"vmess.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000002","security":"auto","alter_id":0,"network":"tcp","tls":{"enabled":true,"server_name":"vmess-sni.example","insecure":true},"transport":{"type":"ws","path":"/socket","headers":{"Host":"ws-host.example"}}},
                    {"type":"vless","tag":"vless","server":"vless.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000003","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"vless-sni.example","reality":{"enabled":true,"public_key":"jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc","short_id":"abcd"},"utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"grpc","service_name":"TunService"}},
                    {"type":"trojan","tag":"trojan","server":"trojan.example","server_port":443,"password":"trojan-password","tls":{"enabled":true,"server_name":"trojan-sni.example"}},
                    {"type":"hysteria2","tag":"hy2","server":"hy2.example","server_ports":["20000:20002","8443"],"hop_interval":"15s","up_mbps":100,"down_mbps":200,"password":"hy2-password","obfs":{"type":"salamander","password":"obfs-password"},"initial_stream_receive_window":1048576,"initial_connection_receive_window":2097152,"disable_path_mtu_discovery":true,"tls":{"enabled":true,"server_name":"hy2-sni.example","insecure":true,"alpn":["h3"]}},
                    {"type":"tuic","tag":"tuic","server":"tuic.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000004","password":"tuic-password","congestion_control":"bbr","udp_relay_mode":"native","initial_packet_size":1252,"tls":{"enabled":true,"server_name":"tuic-sni.example","alpn":["h3","tuic"]}},
                    {"type":"anytls","tag":"anytls","server":"anytls.example","server_port":443,"password":"anytls-password","network":"tcp","min_idle_session":4,"idle_session_check_interval":"30s","idle_session_timeout":"1m","tls":{"enabled":true,"server_name":"anytls-sni.example"}},
                    {"type":"juicity","tag":"juicity","server":"juicity.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000005","password":"juicity-password","initial_stream_receive_window":8388608,"initial_connection_receive_window":8388608,"tls":{"enabled":true,"server_name":"juicity-sni.example","alpn":["h3"]}}
                  ]
                }"#,
            ),
            None,
        )
        .unwrap();

        assert_eq!(nodes.len(), 9);
        assert_eq!(
            nodes.iter().map(Node::protocol).collect::<Vec<_>>(),
            vec![
                NodeProtocol::SS,
                NodeProtocol::Socks5,
                NodeProtocol::VMess,
                NodeProtocol::VLess,
                NodeProtocol::Trojan,
                NodeProtocol::Hysteria2,
                NodeProtocol::Tuic,
                NodeProtocol::AnyTLS,
                NodeProtocol::Juicity,
            ]
        );

        let vmess = &nodes[2];
        assert_eq!(vmess.network(), Some("tcp"));
        assert_eq!(vmess.transport().unwrap().transport, "ws");
        assert_eq!(
            vmess.transport().unwrap().ws_path.as_deref(),
            Some("/socket")
        );
        assert_eq!(
            vmess.transport().unwrap().ws_host.as_deref(),
            Some("ws-host.example")
        );
        assert_eq!(
            vmess.tls().unwrap().sni.as_deref(),
            Some("vmess-sni.example")
        );
        assert!(vmess.tls().unwrap().skip_cert_verify);

        let vless = nodes[3].vless().unwrap();
        assert_eq!(vless.mode, WireMode::Xudp);
        assert_eq!(vless.transport.transport, "grpc");
        assert_eq!(vless.transport.grpc_service.as_deref(), Some("TunService"));
        assert_eq!(
            vless.tls.reality_public_key.as_deref(),
            Some("jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc")
        );
        assert_eq!(vless.tls.reality_short_id.as_deref(), Some("abcd"));

        let hy2 = nodes[5].hysteria2().unwrap();
        assert_eq!(nodes[5].port, 20_000);
        assert_eq!(hy2.auth.as_deref(), Some("hy2-password"));
        assert_eq!(hy2.obfs.as_deref(), Some("obfs-password"));
        assert_eq!(hy2.up_mbps, Some(100));
        assert_eq!(hy2.down_mbps, Some(200));
        assert_eq!(hy2.port_hopping.as_deref(), Some("20000-20002,8443"));
        assert_eq!(hy2.hop_interval, Some(15));
        assert_eq!(hy2.init_stream_recv_window, Some(1_048_576));
        assert_eq!(hy2.init_conn_recv_window, Some(2_097_152));
        assert_eq!(hy2.disable_mtu_discovery, Some(true));

        let tuic = nodes[6].tuic().unwrap();
        assert_eq!(tuic.congestion.as_deref(), Some("bbr"));
        assert_eq!(tuic.alpn.as_deref(), Some("h3,tuic"));
        assert_eq!(tuic.quic.mtu, Some(1252));

        let anytls = nodes[7].anytls().unwrap();
        assert_eq!(anytls.network.as_deref(), Some("tcp"));
        assert_eq!(anytls.min_idle_session, Some(4));
        assert_eq!(anytls.idle_session_check_interval, Some(30));
        assert_eq!(anytls.idle_session_timeout, Some(60));
    }

    #[test]
    fn sing_box_vless_packet_and_multiplex_modes_are_not_guessed() {
        let nodes = parse_json_subscription(
            json(
                r#"{"outbounds":[
                  {"type":"vless","tag":"default-xudp","server":"one.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000011"},
                  {"type":"vless","tag":"explicit-native","server":"two.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000012","network":"tcp","packet_encoding":""},
                  {"type":"vless","tag":"h2mux","server":"three.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000013","multiplex":{"enabled":true,"protocol":"h2mux","padding":true}},
                  {"type":"vless","tag":"uot","server":"four.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000014","udp_over_tcp":{"enabled":true,"version":2}},
                  {"type":"vless","tag":"mux-explicit-xudp","server":"five.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000019","packet_encoding":"xudp","multiplex":{"enabled":true,"protocol":"h2mux"}}
                ]}"#,
            ),
            None,
        )
        .unwrap();
        assert_eq!(nodes[0].vless().unwrap().mode, WireMode::Xudp);
        assert_eq!(nodes[1].vless().unwrap().mode, WireMode::Legacy);
        assert_eq!(nodes[1].network(), Some("tcp"));
        assert_eq!(nodes[2].vless().unwrap().mode, WireMode::H2muxPadded);
        assert_eq!(nodes[3].vless().unwrap().mode, WireMode::UotV2);
        assert_eq!(nodes[4].vless().unwrap().mode, WireMode::H2mux);
    }

    #[test]
    fn sing_box_empty_grpc_and_tuic_defaults_are_preserved() {
        let nodes = parse_json_subscription(
            json(
                r#"{"outbounds":[
                  {"type":"vless","tag":"grpc-default","server":"one.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000015","transport":{"type":"grpc"}},
                  {"type":"vless","tag":"grpc-empty","server":"two.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000016","transport":{"type":"grpc","service_name":""}},
                  {"type":"tuic","tag":"tuic-missing-password","server":"three.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000017","tls":{"enabled":true}},
                  {"type":"tuic","tag":"tuic-empty-password","server":"four.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000018","password":"","tls":{"enabled":true}}
                ]}"#,
            ),
            None,
        )
        .unwrap();

        assert_eq!(nodes.len(), 4);
        assert_eq!(
            nodes[0].transport().unwrap().grpc_service.as_deref(),
            Some("")
        );
        assert_eq!(
            nodes[1].transport().unwrap().grpc_service.as_deref(),
            Some("")
        );
        assert!(nodes[2].tuic().unwrap().password.is_none());
        assert!(nodes[3].tuic().unwrap().password.is_none());
    }

    #[test]
    fn malformed_nodes_do_not_poison_valid_siblings() {
        let nodes = parse_json_subscription(
            json(
                r#"{"outbounds":[
                  {"type":"selector","tag":"select","outbounds":["good"]},
                  {"type":"vless","tag":"bad-packet-mode","server":"bad.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000021","packet_encoding":"packetaddr"},
                  {"type":"vless","tag":"unsupported-native-udp","server":"native.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000024","packet_encoding":""},
                  {"type":"hysteria2","tag":"bad-hop-range","server":"bad-hop.example","server_ports":["9000:8000"],"password":"password","tls":{"enabled":true}},
                  {"type":"hysteria2","tag":"bad-hy2-alpn","server":"bad-hy2.example","server_port":443,"password":"password","tls":{"enabled":true,"alpn":["hq-29"]}},
                  {"type":"juicity","tag":"bad-juicity-alpn","server":"bad-juicity.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000022","password":"password","tls":{"enabled":true,"alpn":["hq-29"]}},
                  {"type":"juicity","tag":"bad-window","server":"bad-window.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000023","password":"password","initial_stream_receive_window":1048576,"tls":{"enabled":true,"alpn":["h3"]}},
                  {"type":"tuic","tag":"missing-tuic-uuid","server":"missing-tuic.example","server_port":443,"password":"password","tls":{"enabled":true}},
                  {"type":"shadowsocks","tag":"plugin","server":"plugin.example","server_port":8388,"method":"aes-256-gcm","password":"password","plugin":"v2ray-plugin"},
                  {"type":"shadowsocks","tag":"good","server":"good.example","server_port":8388,"method":"aes-256-gcm","password":"password"}
                ]}"#,
            ),
            None,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "good");
        assert_eq!(nodes[0].protocol(), NodeProtocol::SS);
    }

    #[test]
    fn malformed_or_unrepresentable_json_inputs_fail_without_echoing_values() {
        for input in [
            r#"{"outbounds":[{"type":"vless","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","packet_encoding":"packetaddr"}]}"#,
            r#"{"outbounds":[{"type":"vmess","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","security":"chacha20-poly1305"}]}"#,
            r#"{"outbounds":[{"type":"vless","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","packet_encoding":"","multiplex":{"enabled":true,"protocol":"yamux"}}]}"#,
            r#"{"outbounds":[{"type":"trojan","server":"secret.example","server_port":443,"password":"secret-password","tls":{"enabled":true},"transport":{"type":"http","path":"/secret"}}]}"#,
            r#"{"outbounds":[{"type":"trojan","server":"secret.example","server_port":443,"password":"secret-password"}]}"#,
            r#"{"outbounds":[{"type":"vless","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","detour":"secret-hop"}]}"#,
            r#"{"version":3,"servers":[{"server":"secret.example","server_port":8388,"method":"aes-256-gcm","password":"secret-password"}]}"#,
        ] {
            let error = parse_json_subscription(json(input), None)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret"));
            assert!(!error.contains("00000000-0000-4000-8000-000000000031"));
        }
    }

    #[test]
    fn structural_or_unknown_only_sing_box_body_is_rejected() {
        for input in [
            r#"{"outbounds":[]}"#,
            r#"{"outbounds":[{"type":"selector","tag":"select","outbounds":[]},{"type":"direct","tag":"direct"},{"type":"http","tag":"unsupported","server":"proxy.example","server_port":8080}]}"#,
        ] {
            assert!(parse_json_subscription(json(input), None).is_err());
        }
    }

    #[test]
    fn configured_sip008_plugin_is_not_imported_as_plain_shadowsocks() {
        assert!(
            parse_json_subscription(
                json(
                    r#"{"version":1,"servers":[{"remarks":"plugin-node","server":"ss.example","server_port":8388,"method":"aes-256-gcm","password":"password","plugin":"v2ray-plugin","plugin_opts":"mode=websocket"}]}"#,
                ),
                None,
            )
            .is_err()
        );
    }
}
