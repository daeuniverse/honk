//! Build typed nodes from the shared Clash-shaped import vocabulary.

mod fields;
pub(super) mod options;

use honk_config::node::{Node, OutboundConfig};
use honk_config::options::vocab::{optional_flow, packet_network, stream_transport};
use honk_config::types::NodeProtocol;
use serde_yaml::Mapping;

pub(super) use self::fields::duration_secs as parse_feed_duration_secs;
use self::fields::{
    active as yaml_active, active_for_key as yaml_active_for_key, bool_alias as yaml_bool_alias,
    duration_alias as yaml_duration_alias, list_alias as yaml_list_alias, optional_text_alias,
    ports as yaml_ports, rate_alias as yaml_rate_alias, raw_alias as yaml_alias, text as yaml_text,
    text_alias as yaml_text_alias, u64_alias as yaml_u64_alias,
};
use super::yaml_value;

const STREAM_WINDOW_KEYS: &[&str] = &[
    "initial-stream-receive-window",
    "initial_stream_receive_window",
    "init-stream-receive-window",
    "init_stream_receive_window",
    "initStreamReceiveWindow",
];
const CONN_WINDOW_KEYS: &[&str] = &[
    "initial-conn-receive-window",
    "initial_conn_receive_window",
    "init-conn-receive-window",
    "init_conn_receive_window",
    "initConnReceiveWindow",
];
const QUIC_MTU_KEYS: &[&str] = &["mtu", "quic-mtu", "quic_mtu"];

struct ProxySource {
    protocol: NodeProtocol,
    name: String,
    server: String,
    port: u16,
    udp: Option<bool>,
    tls_explicit: Option<bool>,
    tls_enabled: bool,
}

fn supports_tls(protocol: NodeProtocol) -> bool {
    matches!(
        protocol,
        NodeProtocol::Trojan
            | NodeProtocol::VMess
            | NodeProtocol::VLess
            | NodeProtocol::Hysteria2
            | NodeProtocol::Tuic
            | NodeProtocol::Juicity
            | NodeProtocol::AnyTLS
    )
}

fn supports_stream(protocol: NodeProtocol) -> bool {
    matches!(
        protocol,
        NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess
    )
}

fn supports_quic(protocol: NodeProtocol) -> bool {
    matches!(
        protocol,
        NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity
    )
}

fn has_active(mapping: &Mapping, keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| yaml_value(mapping, key).is_some_and(yaml_active))
}

fn has_active_for_key(mapping: &Mapping, keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| yaml_value(mapping, key).is_some_and(|value| yaml_active_for_key(key, value)))
}

fn reject_active_unless(
    mapping: &Mapping,
    keys: &[&str],
    supported: bool,
    error: &'static str,
) -> Result<(), &'static str> {
    if !supported && has_active(mapping, keys) {
        Err(error)
    } else {
        Ok(())
    }
}

fn protocol_from_name(proxy_type: &str) -> Result<NodeProtocol, &'static str> {
    if proxy_type.eq_ignore_ascii_case("socks5") {
        Ok(NodeProtocol::Socks5)
    } else if proxy_type.eq_ignore_ascii_case("ss")
        || proxy_type.eq_ignore_ascii_case("shadowsocks")
    {
        Ok(NodeProtocol::SS)
    } else if proxy_type.eq_ignore_ascii_case("trojan") {
        Ok(NodeProtocol::Trojan)
    } else if proxy_type.eq_ignore_ascii_case("vmess") {
        Ok(NodeProtocol::VMess)
    } else if proxy_type.eq_ignore_ascii_case("vless") {
        Ok(NodeProtocol::VLess)
    } else if proxy_type.eq_ignore_ascii_case("hysteria2")
        || proxy_type.eq_ignore_ascii_case("hysteria")
    {
        Ok(NodeProtocol::Hysteria2)
    } else if proxy_type.eq_ignore_ascii_case("tuic") {
        Ok(NodeProtocol::Tuic)
    } else if proxy_type.eq_ignore_ascii_case("juicity") {
        Ok(NodeProtocol::Juicity)
    } else if proxy_type.eq_ignore_ascii_case("anytls") {
        Ok(NodeProtocol::AnyTLS)
    } else {
        Err("unsupported proxy type")
    }
}

fn validate_source(mapping: &Mapping) -> Result<ProxySource, &'static str> {
    let proxy_type = yaml_text_alias(mapping, &["type"])?.ok_or("proxy type is missing")?;
    let protocol = protocol_from_name(&proxy_type)?;
    if protocol == NodeProtocol::VLess && yaml_value(mapping, "vless_mode").is_some() {
        return Err("VLESS vless_mode was removed");
    }

    reject_active_unless(
        mapping,
        &["plugin", "plugin-opts", "plugin_opts"],
        false,
        "proxy plugins are unsupported",
    )?;
    if !supports_tls(protocol)
        && has_active_for_key(
            mapping,
            &[
                "tls",
                "servername",
                "server-name",
                "sni",
                "alpn",
                "skip-cert-verify",
                "skip_cert_verify",
                "insecure",
                "pin-sha256",
                "pin_sha256",
                "reality-opts",
            ],
        )
    {
        return Err("TLS settings are unsupported for this protocol");
    }
    reject_active_unless(
        mapping,
        &[
            "ws-opts",
            "ws-path",
            "ws-host",
            "ws-headers",
            "grpc-opts",
            "grpc-service",
        ],
        supports_stream(protocol),
        "stream transport settings are unsupported for this protocol",
    )?;
    reject_active_unless(
        mapping,
        &["network"],
        supports_stream(protocol) || protocol == NodeProtocol::AnyTLS,
        "network settings are unsupported for this protocol",
    )?;
    reject_active_unless(
        mapping,
        &["flow"],
        supports_stream(protocol),
        "VLESS flow is unsupported for this protocol",
    )?;
    reject_active_unless(
        mapping,
        &["cipher", "encryption"],
        matches!(
            protocol,
            NodeProtocol::SS | NodeProtocol::VMess | NodeProtocol::VLess
        ),
        "encryption settings are unsupported for this protocol",
    )?;
    if protocol != NodeProtocol::VLess
        && has_active_for_key(
            mapping,
            &[
                "packet-encoding",
                "packet_encoding",
                "packet-addr",
                "packet_addr",
                "xudp",
                "mux",
                "smux",
                "multiplex",
                "udp-over-tcp",
                "udp_over_tcp",
            ],
        )
    {
        return Err("VLESS packet wrappers are unsupported for this protocol");
    }

    let udp = yaml_bool_alias(mapping, &["udp"])?;
    let udp_capable = matches!(
        protocol,
        NodeProtocol::SS
            | NodeProtocol::Trojan
            | NodeProtocol::VLess
            | NodeProtocol::Socks5
            | NodeProtocol::Hysteria2
            | NodeProtocol::Tuic
            | NodeProtocol::Juicity
            | NodeProtocol::AnyTLS
    );
    let udp_restrictable = matches!(
        protocol,
        NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess | NodeProtocol::AnyTLS
    );
    if udp == Some(true) && !udp_capable {
        return Err("UDP capability is unsupported for this protocol");
    }
    if udp == Some(false) && !udp_restrictable {
        return Err("UDP restriction is unsupported for this protocol");
    }

    reject_active_unless(
        mapping,
        &[
            "obfs",
            "obfs-password",
            "obfs_password",
            "ports",
            "mport",
            "port-hopping",
            "port_hopping",
            "up",
            "down",
            "upload-bandwidth",
            "download-bandwidth",
            "up-speed",
            "down-speed",
            "up_mbps",
            "down_mbps",
            "hop-interval",
            "hop_interval",
            "mhop",
        ],
        protocol == NodeProtocol::Hysteria2,
        "Hysteria2 options are unsupported for this protocol",
    )?;
    reject_active_unless(
        mapping,
        &[
            "disable-mtu-discovery",
            "disable-path-mtu-discovery",
            "disablePathMTUDiscovery",
        ],
        protocol == NodeProtocol::Hysteria2,
        "Hysteria2 MTU discovery options are unsupported",
    )?;
    if !supports_quic(protocol)
        && (has_active(mapping, QUIC_MTU_KEYS)
            || has_active(mapping, STREAM_WINDOW_KEYS)
            || has_active(mapping, CONN_WINDOW_KEYS))
    {
        return Err("QUIC options are unsupported for this protocol");
    }

    let server = yaml_text_alias(mapping, &["server"])?
        .filter(|value| !value.trim().is_empty())
        .ok_or("proxy server is missing")?;
    let port = yaml_u64_alias(mapping, &["port"])?
        .and_then(|value| u16::try_from(value).ok())
        .ok_or("proxy port is invalid")?;
    let name = yaml_text_alias(mapping, &["name"])?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("{proxy_type}-{server}:{port}"));
    let tls_explicit = yaml_bool_alias(mapping, &["tls"])?;
    let mandatory_tls = matches!(
        protocol,
        NodeProtocol::Trojan
            | NodeProtocol::Hysteria2
            | NodeProtocol::Tuic
            | NodeProtocol::Juicity
            | NodeProtocol::AnyTLS
    );
    let tls_enabled = tls_explicit.unwrap_or(mandatory_tls);
    if mandatory_tls && !tls_enabled {
        return Err("this imported protocol requires TLS");
    }

    Ok(ProxySource {
        protocol,
        name,
        server,
        port,
        udp,
        tls_explicit,
        tls_enabled,
    })
}

fn apply_protocol(mapping: &Mapping, node: &mut Node) -> Result<(), &'static str> {
    let username = yaml_text_alias(mapping, &["username"])?;
    let password = yaml_text_alias(mapping, &["password"])?;
    let cipher = yaml_text_alias(mapping, &["cipher"])?;

    match &mut node.outbound {
        OutboundConfig::Shadowsocks(config) => {
            config.password = password;
            config.encryption = cipher;
        }
        OutboundConfig::Socks5(config) => {
            config.username = username;
            config.password = password;
        }
        OutboundConfig::Trojan(config) => config.password = password,
        OutboundConfig::Vmess(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(password);
            config.encryption = fields::vmess_cipher_alias(mapping, &["encryption", "cipher"])?;
        }
        OutboundConfig::Vless(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(password);
            config.encryption = yaml_text_alias(mapping, &["encryption"])?.or(cipher);
            let flow = optional_text_alias(mapping, &["flow"])?;
            config.flow = optional_flow(flow.as_deref())
                .map_err(|_| "VLESS flow is unsupported")?
                .map(str::to_owned);
            let (udp_encoding, multiplex, udp_enabled) =
                options::parse_vless_external_options(mapping)?;
            config.udp_encoding = udp_encoding;
            config.multiplex = multiplex;
            if !udp_enabled {
                config.network = Some("tcp".into());
            }
        }
        OutboundConfig::Hysteria2(config) => {
            config.auth = yaml_text_alias(mapping, &["auth"])?.or(password);
            if let Some(obfs) = yaml_text_alias(mapping, &["obfs"])? {
                if !obfs.eq_ignore_ascii_case("salamander") {
                    return Err("unsupported Hysteria2 obfuscation algorithm");
                }
                config.obfs = yaml_text_alias(mapping, &["obfs-password", "obfs_password"])?
                    .filter(|password| !password.trim().is_empty())
                    .ok_or("Hysteria2 salamander password is missing")
                    .map(Some)?;
            } else if ["obfs-password", "obfs_password"].iter().any(|key| {
                yaml_value(mapping, key)
                    .is_some_and(|value| !matches!(value, serde_yaml::Value::Null))
            }) {
                return Err("Hysteria2 obfs-password requires salamander");
            }
        }
        OutboundConfig::Tuic(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(username);
            config.password = password;
        }
        OutboundConfig::Juicity(config) => {
            config.uuid = yaml_text_alias(mapping, &["uuid"])?.or(username);
            config.password = password;
        }
        OutboundConfig::AnyTls(config) => {
            config.password = password;
            config.min_idle_session =
                yaml_u64_alias(mapping, &["min-idle-session", "min_idle_session"])?
                    .map(|value| {
                        usize::try_from(value).map_err(|_| "AnyTLS session count is too large")
                    })
                    .transpose()?;
            config.idle_session_check_interval = yaml_duration_alias(
                mapping,
                &["idle-session-check-interval", "idle_session_check_interval"],
            )?;
            config.idle_session_timeout =
                yaml_duration_alias(mapping, &["idle-session-timeout", "idle_session_timeout"])?;
        }
        OutboundConfig::Direct | OutboundConfig::Block => unreachable!(),
    }
    Ok(())
}
fn resolve_anytls_network(
    mapping: &Mapping,
    udp: Option<bool>,
) -> Result<Option<String>, &'static str> {
    let mut selected = None::<(&str, bool)>;
    for key in ["anytls-network", "network"] {
        let Some(value) = yaml_value(mapping, key) else {
            continue;
        };
        if matches!(value, serde_yaml::Value::Null) {
            continue;
        }
        let serde_yaml::Value::String(value) = value else {
            return Err("AnyTLS network must be a string");
        };
        let Some(network_udp) = packet_network(value)? else {
            continue;
        };
        match selected {
            None => selected = Some((value, network_udp)),
            Some((_, previous)) if previous == network_udp => {}
            Some(_) => return Err("AnyTLS network aliases conflict"),
        }
    }
    if let (Some((_, network_udp)), Some(udp)) = (selected, udp)
        && network_udp != udp
    {
        return Err("AnyTLS network conflicts with udp");
    }
    if let Some((value, _)) = selected {
        return Ok(Some(value.to_owned()));
    }
    Ok(udp.map(|udp| if udp { "tcp,udp" } else { "tcp" }.to_owned()))
}

fn apply_stream(mapping: &Mapping, node: &mut Node, udp: Option<bool>) -> Result<(), &'static str> {
    if let Some(config) = node.anytls_mut() {
        config.network = resolve_anytls_network(mapping, udp)?;
    } else {
        if let Some(network) =
            yaml_text_alias(mapping, &["network"])?.filter(|network| !network.trim().is_empty())
            && let Some(transport) = node.transport_mut()
        {
            stream_transport(&network)?;
            transport.transport = network;
        }
        if let Some(udp) = udp {
            let network = if udp { "tcp,udp" } else { "tcp" }.to_string();
            match &mut node.outbound {
                OutboundConfig::Trojan(config) => config.network = Some(network),
                OutboundConfig::Vmess(config) => config.network = Some(network),
                OutboundConfig::Vless(config) => config.network = Some(network),
                _ => {}
            }
        }
    }

    if let Some(transport) = node.transport() {
        if transport.transport != "ws"
            && has_active(mapping, &["ws-opts", "ws-path", "ws-host", "ws-headers"])
        {
            return Err("websocket options require websocket transport");
        }
        if transport.transport != "grpc"
            && has_active(mapping, &["grpc-opts", "grpc-service", "grpc_service"])
        {
            return Err("gRPC options require gRPC transport");
        }
    }
    if let Some(transport) = node.transport_mut() {
        if let Some(options) = yaml_value(mapping, "ws-opts").filter(|value| yaml_active(value)) {
            let options = options.as_mapping().ok_or("ws-opts must be a mapping")?;
            transport.ws_path = yaml_text_alias(options, &["path"])?;
            if let Some(headers) = yaml_value(options, "headers") {
                let headers = headers
                    .as_mapping()
                    .ok_or("ws-opts.headers must be a mapping")?;
                for (key, value) in headers {
                    let key = key.as_str().ok_or("websocket header name is invalid")?;
                    if !key.eq_ignore_ascii_case("host")
                        && !matches!(value, serde_yaml::Value::Null)
                    {
                        return Err("unsupported websocket header");
                    }
                }
                transport.ws_host = headers.iter().find_map(|(key, value)| {
                    key.as_str()
                        .filter(|key| key.eq_ignore_ascii_case("host"))
                        .and_then(|_| yaml_text(value).ok().flatten())
                        .filter(|value| !value.trim().is_empty())
                });
            }
        }
        transport.ws_path = transport
            .ws_path
            .take()
            .or(yaml_text_alias(mapping, &["ws-path"])?.filter(|value| !value.trim().is_empty()));
        if transport.ws_host.is_none() {
            transport.ws_host =
                yaml_text_alias(mapping, &["ws-headers"])?.filter(|value| !value.trim().is_empty());
        }
        if transport.ws_host.is_none() {
            transport.ws_host =
                yaml_text_alias(mapping, &["ws-host"])?.filter(|value| !value.trim().is_empty());
        }
        if let Some(options) = yaml_value(mapping, "grpc-opts").filter(|value| yaml_active(value)) {
            let options = options.as_mapping().ok_or("grpc-opts must be a mapping")?;
            transport.grpc_service =
                yaml_text_alias(options, &["grpc-service-name", "grpc_service_name"])?;
        }
        transport.grpc_service = transport
            .grpc_service
            .take()
            .or(yaml_text_alias(mapping, &["grpc-service", "grpc_service"])?);
    }
    Ok(())
}

fn apply_reality(
    mapping: &Mapping,
    node: &mut Node,
    protocol: NodeProtocol,
    tls_explicit: Option<bool>,
) -> Result<(), &'static str> {
    let Some(value) = yaml_value(mapping, "reality-opts") else {
        return Ok(());
    };
    if !yaml_active(value) {
        return Ok(());
    }
    if !supports_stream(protocol) {
        return Err("REALITY is unsupported for this protocol");
    }
    if tls_explicit == Some(false) {
        return Err("REALITY conflicts with tls=false");
    }
    let reality = value.as_mapping().ok_or("reality-opts must be a mapping")?;
    let public_key = yaml_text_alias(reality, &["public-key", "public_key"])?
        .filter(|value| !value.trim().is_empty())
        .ok_or("REALITY public key is missing")?;
    let short_id = yaml_text_alias(reality, &["short-id", "short_id"])?;
    let spider_x = yaml_text_alias(reality, &["spider-x", "spider_x"])?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/".to_string());
    let tls = node.tls_mut().ok_or("REALITY requires TLS")?;
    tls.enabled = true;
    tls.reality_public_key = Some(public_key);
    tls.reality_short_id = short_id;
    tls.reality_spider_x = Some(spider_x);
    Ok(())
}

fn apply_tls(
    mapping: &Mapping,
    node: &mut Node,
    protocol: NodeProtocol,
    tls_explicit: Option<bool>,
    tls_enabled: bool,
) -> Result<(), &'static str> {
    if yaml_bool_alias(mapping, &["disable-sni", "disable_sni"])? == Some(true) {
        return Err("disable-sni is unsupported");
    }
    if let Some(tls) = node.tls_mut() {
        tls.enabled = tls_enabled;
        tls.sni = optional_text_alias(mapping, &["servername", "server-name", "sni"])?;
        tls.skip_cert_verify = yaml_bool_alias(
            mapping,
            &["skip-cert-verify", "skip_cert_verify", "insecure"],
        )?
        .unwrap_or(false);
        tls.pin_sha256 = yaml_text_alias(mapping, &["pin-sha256", "pin_sha256"])?;
        if !supports_quic(protocol)
            && let Some(alpn) = yaml_value(mapping, "alpn")
        {
            tls.alpn = fields::alpn_list(alpn)?;
        }
    }
    apply_reality(mapping, node, protocol, tls_explicit)
}

fn apply_quic(mapping: &Mapping, node: &mut Node) -> Result<(), &'static str> {
    let protocol = node.protocol();
    if matches!(protocol, NodeProtocol::Hysteria2 | NodeProtocol::Juicity)
        && yaml_value(mapping, "alpn").is_some_and(yaml_active)
    {
        let alpn = yaml_list_alias(mapping, &["alpn"])?.unwrap_or_default();
        if !alpn.split(',').all(|value| value.trim() == "h3") {
            return Err("unsupported fixed QUIC ALPN");
        }
    }
    if fields::tuic_relay_alias(mapping)?.is_some() && protocol != NodeProtocol::Tuic {
        return Err("unsupported TUIC UDP relay mode");
    }
    if protocol == NodeProtocol::Juicity {
        for keys in [STREAM_WINDOW_KEYS, CONN_WINDOW_KEYS] {
            if has_active(mapping, keys)
                && let Some(window) = yaml_u64_alias(mapping, keys)?
                && !matches!(window, 0 | 8_388_608)
            {
                return Err("Juicity receive-window override is unsupported");
            }
        }
    }

    match &mut node.outbound {
        OutboundConfig::Hysteria2(config) => {
            config.up_mbps =
                yaml_rate_alias(mapping, &["up", "upload-bandwidth", "up-speed", "up_mbps"])?;
            config.down_mbps = yaml_rate_alias(
                mapping,
                &["down", "download-bandwidth", "down-speed", "down_mbps"],
            )?;
            let ports = yaml_alias(mapping, &["ports"])?
                .map(yaml_ports)
                .transpose()?
                .flatten();
            let mport = yaml_text_alias(mapping, &["mport", "port-hopping", "port_hopping"])?
                .map(|value| value.replace(':', "-"));
            if ports.is_some() && mport.is_some() {
                return Err("Hysteria2 port hopping aliases conflict");
            }
            config.port_hopping = ports.or(mport);
            config.hop_interval =
                yaml_duration_alias(mapping, &["hop-interval", "hop_interval", "mhop"])?;
            config.init_stream_recv_window = yaml_u64_alias(mapping, STREAM_WINDOW_KEYS)?;
            config.init_conn_recv_window = yaml_u64_alias(mapping, CONN_WINDOW_KEYS)?;
            config.disable_mtu_discovery = yaml_bool_alias(
                mapping,
                &[
                    "disable-mtu-discovery",
                    "disable-path-mtu-discovery",
                    "disablePathMTUDiscovery",
                ],
            )?;
        }
        OutboundConfig::Tuic(config) => {
            config.congestion = yaml_text_alias(
                mapping,
                &[
                    "congestion-controller",
                    "congestion-control",
                    "congestion_control",
                    "congestion",
                ],
            )?;
            config.alpn = yaml_list_alias(mapping, &["alpn"])?;
            config.init_stream_recv_window = yaml_u64_alias(mapping, STREAM_WINDOW_KEYS)?;
            config.init_conn_recv_window = yaml_u64_alias(mapping, CONN_WINDOW_KEYS)?;
        }
        _ => {}
    }

    if let Some(mtu) = yaml_u64_alias(mapping, QUIC_MTU_KEYS)? {
        let mtu = u16::try_from(mtu).map_err(|_| "QUIC MTU is invalid")?;
        if !(1200..=65527).contains(&mtu) {
            return Err("QUIC MTU is invalid");
        }
        match &mut node.outbound {
            OutboundConfig::Hysteria2(config) => config.quic.mtu = Some(mtu),
            OutboundConfig::Tuic(config) => config.quic.mtu = Some(mtu),
            OutboundConfig::Juicity(config) => config.quic.mtu = Some(mtu),
            _ => {}
        }
    }
    Ok(())
}

fn validate_imported_node(node: &Node) -> Result<(), &'static str> {
    fn nonempty(value: Option<&String>) -> Result<&String, &'static str> {
        value
            .filter(|value| !value.trim().is_empty())
            .ok_or("required proxy credential is missing")
    }

    match &node.outbound {
        OutboundConfig::Shadowsocks(config) => {
            nonempty(config.password.as_ref())?;
            nonempty(config.encryption.as_ref())?;
        }
        OutboundConfig::Trojan(config) => {
            nonempty(config.password.as_ref())?;
        }
        OutboundConfig::Juicity(config) => {
            nonempty(config.password.as_ref())?;
        }
        OutboundConfig::AnyTls(config) => {
            nonempty(config.password.as_ref())?;
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn parse_clash_proxy(
    mapping: &Mapping,
    subscription_id: Option<uuid::Uuid>,
) -> Result<Node, &'static str> {
    let ProxySource {
        protocol,
        name,
        server,
        port,
        udp,
        tls_explicit,
        tls_enabled,
    } = validate_source(mapping)?;
    let mut node = Node {
        name,
        address: format!("{server}:{port}"),
        host: server,
        port,
        outbound: OutboundConfig::from_protocol(protocol),
        subscription_id,
        ..Default::default()
    };

    apply_protocol(mapping, &mut node)?;
    apply_stream(mapping, &mut node, udp)?;
    apply_tls(mapping, &mut node, protocol, tls_explicit, tls_enabled)?;
    apply_quic(mapping, &mut node)?;
    if let Some(config) = node.vless_mut() {
        config.normalize();
    }
    validate_imported_node(&node)?;
    node.validate()
        .map_err(|_| "invalid imported node protocol settings")?;
    node.id = node.derive_id();
    Ok(node)
}

#[cfg(test)]
mod tests {
    use honk_config::subscription::Subscription;
    use honk_config::types::SubscriptionType;

    use super::super::parse_subscription_content;

    #[test]
    fn public_parser_compares_aliases_by_their_typed_meaning() {
        let subscription = Subscription {
            sub_type: SubscriptionType::Clash,
            ..Default::default()
        };
        let nodes = parse_subscription_content(
            &subscription,
            r#"
proxies:
  - name: conflicting-text
    type: trojan
    server: text.example
    port: 443
    password: secret
    servername: "001"
    server-name: "1"
  - name: equivalent-integers
    type: hysteria2
    server: integer.example
    port: 443
    mtu: "1200"
    quic-mtu: 1200
"#,
        )
        .unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "equivalent-integers");
        assert_eq!(nodes[0].hysteria2().unwrap().quic.mtu, Some(1200));
    }
}
