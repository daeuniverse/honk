//! Adapters for the comma-separated records emitted by Surge-family clients.
//!
//! Surge, Surfboard and Loon put the display name before the protocol, while
//! Quantumult X puts the protocol before an endpoint. Both normalize to the
//! Clash key vocabulary so the common parser owns Node
//! construction and validation.

use std::collections::HashMap;

use serde_yaml::{Mapping, Value};

use super::Node;

mod fields;
use fields::{Field, split_fields};

/// Parse Surge/Surfboard/Loon and Quantumult X record bodies.
///
/// The body may be a complete profile or a plain record list. Unsupported
/// records are discarded individually so supported siblings survive.
pub(super) fn parse_records_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let body = content;
    let mut records = Vec::<Value>::new();
    let mut section = None::<String>;
    let has_sections = body
        .lines()
        .map(str::trim)
        .any(|line| section_name(line).is_some());
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = section_name(line) {
            section = Some(name);
            continue;
        }
        if has_sections && !section.as_deref().is_some_and(is_record_section) {
            continue;
        }

        let Some(fields) = split_fields(line) else {
            tracing::warn!(
                category = "malformed-record",
                "skipping subscription record"
            );
            continue;
        };
        match parse_record(&fields) {
            Ok(record) => records.push(Value::Mapping(record)),
            Err(reason) => tracing::debug!(
                category = "unsupported-record",
                reason,
                "skipping subscription record"
            ),
        }
    }

    if records.is_empty() {
        anyhow::bail!("no supported records found in subscription");
    }
    super::parse_clash_proxies(&records, subscription_id)
}

fn section_name(line: &str) -> Option<String> {
    line.strip_prefix('[')
        .and_then(|line| line.strip_suffix(']'))
        .map(|name| name.trim().to_ascii_lowercase())
}

fn is_record_section(name: &str) -> bool {
    matches!(name, "proxy" | "server_local")
}

type RecordResult<T> = Result<T, &'static str>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Dialect {
    Named,
    QuantumultX,
}

fn parse_record(fields: &[Field]) -> RecordResult<Mapping> {
    let (left, right) = record_header(fields.first().ok_or("record header is missing")?)
        .ok_or("record header is malformed")?;
    if let Some(protocol) = canonical_type(right) {
        parse_named(fields, protocol)
    } else if let Some(protocol) = canonical_type(left)
        && parse_endpoint(right).is_some()
    {
        parse_qx(fields, protocol)
    } else {
        Err("record header is unsupported")
    }
}

fn parse_named(fields: &[Field], protocol: &'static str) -> RecordResult<Mapping> {
    let (name, _) = record_header(fields.first().ok_or("record header is missing")?)
        .ok_or("record header is malformed")?;
    let server = normalize_host(
        fields
            .get(1)
            .ok_or("record server is missing")?
            .value
            .trim(),
    );
    if server.is_empty() {
        return Err("record server is missing");
    }
    let port = parse_port(fields.get(2).ok_or("record port is missing")?.value.trim())
        .ok_or("record port is invalid")?;
    let (positions, mut options) = positional_options(fields, 3, Dialect::Named)?;
    options.remove("tag");
    normalize_protocol(
        Dialect::Named,
        protocol,
        name.to_string(),
        server,
        port,
        &positions,
        options,
    )
}

fn parse_qx(fields: &[Field], protocol: &'static str) -> RecordResult<Mapping> {
    let (_, endpoint) = record_header(fields.first().ok_or("record header is missing")?)
        .ok_or("record header is malformed")?;
    let (server, port) = parse_endpoint(endpoint).ok_or("record endpoint is invalid")?;
    let (positions, mut options) = positional_options(fields, 1, Dialect::QuantumultX)?;
    if !positions.is_empty() {
        return Err("Quantumult X record has a positional field");
    }
    let name = options.remove("tag").unwrap_or_default();
    normalize_protocol(
        Dialect::QuantumultX,
        protocol,
        name,
        server,
        port,
        &positions,
        options,
    )
}

fn normalize_protocol(
    dialect: Dialect,
    protocol: &'static str,
    name: String,
    server: String,
    port: u16,
    positions: &[String],
    mut options: HashMap<String, String>,
) -> RecordResult<Mapping> {
    consume_record_controls(protocol, &mut options)?;
    let mut map = base_mapping(protocol, name, server, port);
    apply_security(&mut map, dialect, protocol, &mut options)?;
    apply_protocol(&mut map, dialect, protocol, positions, &mut options)?;
    apply_udp_options(&mut map, &mut options)?;
    if options.values().any(|value| !is_disabled_wire_value(value)) {
        return Err("record has an unsupported active option");
    }
    Ok(map)
}

fn record_header(field: &Field) -> Option<(&str, &str)> {
    let delimiter = field.unquoted_equals?;
    let (left, right) = field.value.split_at(delimiter);
    Some((left.trim(), right.get(1..)?.trim()))
}

fn consume_record_controls(
    protocol: &str,
    options: &mut HashMap<String, String>,
) -> RecordResult<()> {
    if take_any_active(
        options,
        &[
            "proxy",
            "underlying-proxy",
            "underlying_proxy",
            "dialer-proxy",
            "dialer_proxy",
            "chain",
            "chained",
            "proxy-policy",
            "proxy_policy",
        ],
    ) {
        return Err("record chaining is unsupported");
    }
    if let Some(value) = take_raw(options, &["mux"]) {
        let enabled = parse_bool(&value).unwrap_or_else(|| !value.eq_ignore_ascii_case("none"));
        if enabled {
            return Err("record multiplexing is unsupported");
        }
    }
    if let Some(enabled) = take_bool(options, &["aead"])?
        && ((protocol == "vmess" && !enabled) || (protocol != "vmess" && enabled))
    {
        return Err("record AEAD mode is unsupported");
    }
    if take_any_matching(options, &["udp-over-tcp", "udp_over_tcp"], |value| {
        !is_disabled_wire_value(value)
    }) {
        return Err("record UDP-over-TCP mode is unsupported");
    }
    if take_any_active(options, &["ssr-protocol", "ssr-protocol-param"]) {
        return Err("record SSR mode is unsupported");
    }
    Ok(())
}

fn apply_udp_options(map: &mut Mapping, options: &mut HashMap<String, String>) -> RecordResult<()> {
    let udp = take_bool(options, &["udp"])?;
    let relay = take_bool(options, &["udp-relay"])?;
    if let (Some(udp), Some(relay)) = (udp, relay)
        && udp != relay
    {
        return Err("record UDP aliases conflict");
    }
    if let Some(enabled) = relay.or(udp) {
        put_bool(map, "udp", enabled);
    }
    Ok(())
}

fn is_disabled_wire_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "none" | "off"
    )
}

fn base_mapping(protocol: &str, name: String, server: String, port: u16) -> Mapping {
    let mut map = Mapping::new();
    put_str(&mut map, "type", protocol);
    if !name.trim().is_empty() {
        put_str(&mut map, "name", name);
    }
    put_str(&mut map, "server", server);
    put_u64(&mut map, "port", port.into());
    map
}

fn positional_options(
    fields: &[Field],
    start: usize,
    dialect: Dialect,
) -> RecordResult<(Vec<String>, HashMap<String, String>)> {
    let mut positions = Vec::new();
    let mut options = HashMap::new();
    for field in fields.iter().skip(start) {
        if field.value.trim().is_empty() {
            continue;
        }
        if field.quoted || (dialect == Dialect::Named && looks_like_base64_credential(&field.value))
        {
            positions.push(if field.quoted {
                field.value.clone()
            } else {
                field.value.trim().to_string()
            });
            continue;
        }
        let Some((key, value)) = field.value.split_once('=') else {
            positions.push(field.value.trim().to_string());
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err("record option key is empty");
        }
        if is_harmless_metadata(&key) {
            continue;
        }
        let value = if field.quoted_value {
            value.to_string()
        } else {
            value.trim().to_string()
        };
        options.insert(key, value);
    }
    Ok((positions, options))
}

fn looks_like_base64_credential(value: &str) -> bool {
    let value = value.trim();
    let body = value.trim_end_matches('=');
    let padding = value.len() - body.len();
    (1..=2).contains(&padding)
        && value.len().is_multiple_of(4)
        && !body.is_empty()
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_'))
}

fn is_harmless_metadata(key: &str) -> bool {
    matches!(
        key,
        "fast-open"
            | "img-url"
            | "img_url"
            | "server-check-url"
            | "server_check_url"
            | "test-url"
            | "test_url"
            | "tfo"
            | "tls13"
    ) || key.ends_with("-note")
        || key.ends_with("_note")
        || key.ends_with("-remark")
        || key.ends_with("_remark")
}

fn apply_protocol(
    map: &mut Mapping,
    dialect: Dialect,
    protocol: &str,
    positions: &[String],
    options: &mut HashMap<String, String>,
) -> RecordResult<()> {
    match protocol {
        "ss" => {
            let cipher = match dialect {
                Dialect::Named => take_option(options, &["encrypt-method", "method", "cipher"])
                    .or_else(|| positions.first().cloned()),
                Dialect::QuantumultX => {
                    take_option(options, &["method", "cipher", "encrypt-method"])
                }
            };
            let password = take_option(options, &["password"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.get(1).cloned())
                    .flatten()
            });
            set_required(map, "cipher", cipher)?;
            set_required(map, "password", password)?;
            if take_any_active(options, &["plugin", "plugin-opts", "plugin_opts"]) {
                return Err("Shadowsocks plugins are unsupported");
            }
            if let Some(obfs) = take_raw(options, &["obfs"])
                && match dialect {
                    Dialect::Named => !obfs.trim().is_empty(),
                    Dialect::QuantumultX => {
                        !obfs.trim().is_empty() && !obfs.eq_ignore_ascii_case("none")
                    }
                }
            {
                return Err("Shadowsocks obfuscation is unsupported");
            }
        }
        "socks5" => {
            let username = take_option(options, &["username"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.first().cloned())
                    .flatten()
            });
            let password = take_option(options, &["password"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.get(1).cloned())
                    .flatten()
            });
            set_optional(map, "username", username);
            set_optional(map, "password", password);
            if dialect == Dialect::QuantumultX
                && take_raw(options, &["obfs"]).is_some_and(|value| !value.trim().is_empty())
            {
                return Err("SOCKS5 obfuscation is unsupported");
            }
        }
        "vmess" => {
            let uuid = match dialect {
                Dialect::Named => take_option(options, &["username", "uuid", "password"])
                    .or_else(|| {
                        positions
                            .iter()
                            .find(|value| looks_like_uuid(value))
                            .cloned()
                    })
                    .or_else(|| positions.get(1).cloned()),
                Dialect::QuantumultX => take_option(options, &["password", "uuid", "username"]),
            };
            set_required(map, "uuid", uuid)?;
            let cipher = match dialect {
                Dialect::Named => take_option(options, &["method", "encryption", "cipher"])
                    .or_else(|| positions.first().filter(|v| !looks_like_uuid(v)).cloned()),
                Dialect::QuantumultX => take_option(options, &["method", "cipher"]),
            };
            set_optional(map, "cipher", cipher);
            if dialect == Dialect::Named {
                apply_transport(map, options, positions)?;
            }
        }
        "trojan" => {
            let password = take_option(options, &["password"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.first().cloned())
                    .flatten()
            });
            set_required(map, "password", password)?;
            if dialect == Dialect::Named {
                apply_transport(map, options, positions)?;
            }
        }
        "vless" => {
            let uuid = match dialect {
                Dialect::Named => take_option(options, &["uuid", "password"])
                    .or_else(|| positions.first().cloned()),
                Dialect::QuantumultX => take_option(options, &["password", "uuid"]),
            };
            set_required(map, "uuid", uuid)?;
            if dialect == Dialect::QuantumultX {
                set_optional(
                    map,
                    "encryption",
                    take_option(options, &["method", "encryption"]),
                );
            }
            set_optional(
                map,
                "flow",
                match dialect {
                    Dialect::Named => take_option(options, &["flow", "vless-flow"]),
                    Dialect::QuantumultX => take_option(options, &["vless-flow", "flow"]),
                },
            );
            if dialect == Dialect::Named {
                apply_transport(map, options, positions)?;
            }
            apply_vless_mode(map, options)?;
        }
        "hysteria2" => {
            let auth = take_option(options, &["password", "auth"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.first().cloned())
                    .flatten()
            });
            set_optional(map, "auth", auth);
            apply_hysteria(map, options)?;
            apply_quic_common(map, options);
        }
        "tuic" => {
            let uuid = take_option(options, &["uuid", "username"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.first().cloned())
                    .flatten()
            });
            let password = take_option(options, &["password"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.get(1).cloned())
                    .flatten()
            });
            set_required(map, "uuid", uuid)?;
            set_optional(map, "password", password);
            apply_quic_common(map, options);
        }
        "juicity" => {
            let uuid = take_option(options, &["uuid", "username"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.first().cloned())
                    .flatten()
            });
            let password = take_option(options, &["password"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.get(1).cloned())
                    .flatten()
            });
            set_required(map, "uuid", uuid)?;
            set_required(map, "password", password)?;
            apply_quic_common(map, options);
        }
        "anytls" => {
            let password = take_option(options, &["password"]).or_else(|| {
                (dialect == Dialect::Named)
                    .then(|| positions.first().cloned())
                    .flatten()
            });
            set_required(map, "password", password)?;
            set_optional(map, "network", take_option(options, &["network"]));
        }
        _ => return Err("record protocol is unsupported"),
    }
    Ok(())
}

fn apply_transport(
    map: &mut Mapping,
    options: &mut HashMap<String, String>,
    positions: &[String],
) -> RecordResult<()> {
    let mut transport = take_option(options, &["transport", "network"]);
    let ws = take_bool(options, &["ws"])?;
    if transport.is_none() && ws == Some(true) {
        transport = Some("ws".to_string());
    }
    let transport = transport.or_else(|| {
        positions
            .iter()
            .find(|value| matches!(value.as_str(), "tcp" | "ws" | "grpc" | "h2" | "httpupgrade"))
            .cloned()
    });
    let Some(transport) = transport else {
        return Ok(());
    };
    let transport = transport.to_ascii_lowercase();
    if !matches!(transport.as_str(), "tcp" | "ws" | "grpc") {
        return Err("record transport is unsupported");
    }
    put_str(map, "network", transport.clone());
    if transport == "ws" {
        set_optional(
            map,
            "ws-path",
            take_option(options, &["ws-path", "path", "obfs-uri"]),
        );
        set_optional(
            map,
            "ws-host",
            take_option(options, &["ws-host", "host", "obfs-host"]),
        );
        if let Some(headers) = take_option(options, &["ws-headers"]) {
            let host = headers
                .split_once(':')
                .filter(|(key, _)| key.trim().eq_ignore_ascii_case("host"))
                .map(|(_, value)| value.trim().to_string())
                .ok_or("record websocket headers are unsupported")?;
            put_str(map, "ws-host", host);
        }
    } else if transport == "grpc" {
        set_optional(
            map,
            "grpc-service",
            take_option(
                options,
                &["grpc-service-name", "grpc-service", "service-name"],
            ),
        );
    }
    Ok(())
}

fn apply_security(
    map: &mut Mapping,
    dialect: Dialect,
    protocol: &str,
    options: &mut HashMap<String, String>,
) -> RecordResult<()> {
    let mut obfs_tls = None;
    let mut obfs_sni = None;
    if matches!(protocol, "vmess" | "trojan" | "vless") {
        match (dialect, take_option(options, &["obfs"])) {
            (Dialect::Named, Some(obfs))
                if !matches!(obfs.to_ascii_lowercase().as_str(), "none" | "tcp") =>
            {
                return Err("record obfuscation is unsupported");
            }
            (Dialect::Named, _) | (Dialect::QuantumultX, None) => {}
            (Dialect::QuantumultX, Some(obfs)) => {
                let obfs = obfs.to_ascii_lowercase();
                match obfs.as_str() {
                    "none" | "tcp" => {}
                    "ws" | "wss" => {
                        put_str(map, "network", "ws");
                        obfs_tls = Some(obfs == "wss");
                        set_optional(map, "ws-path", take_option(options, &["obfs-uri", "path"]));
                        let host = take_option(options, &["obfs-host", "host"]);
                        set_optional(map, "ws-host", host.clone());
                        if obfs == "wss" {
                            obfs_sni = host;
                        }
                    }
                    "over-tls" => {
                        put_str(map, "network", "tcp");
                        obfs_tls = Some(true);
                        obfs_sni = take_option(options, &["obfs-host", "host"]);
                    }
                    _ => return Err("Quantumult X obfuscation is unsupported"),
                }
            }
        }
    }

    let tls = take_bool(options, &["tls"])?;
    let over_tls = take_bool(options, &["over-tls"])?;
    if tls.is_some() && over_tls.is_some() && tls != over_tls {
        return Err("record TLS aliases conflict");
    }
    let mut tls_setting = over_tls.or(tls).or(obfs_tls);
    let security = take_option(options, &["security"]).map(|value| value.to_ascii_lowercase());
    match security.as_deref() {
        None => {}
        Some("none") => tls_setting = Some(false),
        Some("tls" | "reality") => tls_setting = Some(true),
        Some(_) => return Err("record security mode is unsupported"),
    }

    let (public_key, short_id, spider_x) = match dialect {
        Dialect::Named => (
            take_option(options, &["public-key", "reality-public-key"]),
            take_option(options, &["short-id", "reality-short-id"]),
            take_option(options, &["spider-x", "spx"]),
        ),
        Dialect::QuantumultX => (
            take_option(options, &["reality-base64-pubkey", "reality-public-key"]),
            take_option(options, &["reality-hex-shortid", "reality-short-id"]),
            None,
        ),
    };
    let reality_fields = public_key.is_some() || short_id.is_some() || spider_x.is_some();
    let reality_requested = reality_fields || security.as_deref() == Some("reality");
    if reality_requested && !matches!(protocol, "vless" | "trojan") {
        return Err("REALITY is unsupported for this record protocol");
    }
    if reality_fields && security.as_deref() == Some("none") {
        return Err("REALITY conflicts with security=none");
    }
    if reality_requested
        && (tls == Some(false) || over_tls == Some(false) || obfs_tls == Some(false))
    {
        return Err("REALITY conflicts with disabled TLS");
    }
    if reality_requested {
        let public_key = public_key.ok_or("REALITY public key is missing")?;
        let mut reality = Mapping::new();
        put_str(&mut reality, "public-key", public_key);
        if let Some(value) = short_id {
            put_str(&mut reality, "short-id", value);
        }
        if let Some(value) = spider_x {
            put_str(&mut reality, "spider-x", value);
        }
        map.insert(
            Value::String("reality-opts".to_string()),
            Value::Mapping(reality),
        );
        tls_setting = Some(true);
    }
    if let Some(enabled) = tls_setting {
        put_bool(map, "tls", enabled);
    }

    let explicit_skip = take_option(options, &["skip-cert-verify", "allow-insecure", "insecure"])
        .map(|value| parse_bool(&value).ok_or("record boolean option is invalid"))
        .transpose()?;
    let verification = take_bool(options, &["tls-verification"])?;
    if verification == Some(true) && !tls_capable(protocol) {
        return Err("TLS verification is unsupported for this protocol");
    }
    let skip = if tls_capable(protocol) {
        verification.map(|verify| !verify).or(explicit_skip)
    } else {
        explicit_skip
    };
    if let Some(skip) = skip {
        put_bool(map, "skip-cert-verify", skip);
    }

    let qx_cert_pin = take_option(options, &["tls-cert-sha256"]);
    let qx_public_pin = take_option(options, &["tls-pubkey-sha256"]);
    if (qx_cert_pin.is_some() || qx_public_pin.is_some())
        && !(dialect == Dialect::QuantumultX && verification == Some(false))
    {
        return Err("Quantumult X certificate pins are unsupported");
    }
    if let Some(pin) = take_option(options, &["server-cert-fingerprint-sha256"]) {
        if dialect != Dialect::Named {
            return Err("certificate fingerprint is unsupported for this dialect");
        }
        put_str(map, "pin-sha256", pin);
    }
    if take_any_active(options, &["client-cert", "server-cert-verify-name"])
        || take_any_active(
            options,
            &[
                "shadow-tls-password",
                "shadow-tls-sni",
                "shadow-tls-version",
            ],
        )
    {
        return Err("record requires unsupported TLS behavior");
    }

    let servername = take_option(
        options,
        &["servername", "server-name", "sni", "tls-name", "tls-host"],
    )
    .or(obfs_sni);
    if servername
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("off"))
    {
        return Err("disabling SNI is unsupported");
    }
    set_optional(map, "servername", servername);

    if dialect == Dialect::Named {
        set_optional(map, "alpn", take_option(options, &["alpn"]));
    }
    let tls_alpn = take_option(options, &["tls-alpn"]);
    if tls_alpn.is_some() && !(dialect == Dialect::QuantumultX && reality_requested) {
        return Err("custom TLS ALPN is unsupported");
    }
    if let Some(disabled) = take_bool(options, &["tls-no-session-ticket"])?
        && disabled
        && !(dialect == Dialect::QuantumultX && reality_requested)
    {
        return Err("disabling TLS session tickets is unsupported");
    }
    if take_bool(options, &["tls-no-session-reuse"])? == Some(true) {
        return Err("disabling TLS session reuse is unsupported");
    }
    Ok(())
}

fn tls_capable(protocol: &str) -> bool {
    matches!(
        protocol,
        "trojan" | "vmess" | "vless" | "hysteria2" | "tuic" | "juicity" | "anytls"
    )
}

fn apply_vless_mode(map: &mut Mapping, options: &mut HashMap<String, String>) -> RecordResult<()> {
    for key in ["packet-addr", "packet_addr", "packetaddr"] {
        if let Some(value) = options.remove(key)
            && parse_bool(&value).ok_or("record boolean option is invalid")?
        {
            return Err("VLESS packet-addr is unsupported");
        }
    }
    if let Some(value) = take_option(
        options,
        &["packet-encoding", "packet_encoding", "packetencoding"],
    ) {
        if !matches!(value.as_str(), "none" | "xudp" | "") {
            return Err("VLESS packet encoding is unsupported");
        }
        if value == "xudp" {
            put_str(map, "packet-encoding", "xudp");
        }
    }
    Ok(())
}

fn apply_hysteria(map: &mut Mapping, options: &mut HashMap<String, String>) -> RecordResult<()> {
    set_optional(
        map,
        "upload-bandwidth",
        take_option(options, &["upload-bandwidth", "up-mbps", "upmbps"]),
    );
    set_optional(
        map,
        "download-bandwidth",
        take_option(options, &["download-bandwidth", "down-mbps", "downmbps"]),
    );
    set_optional(
        map,
        "mport",
        take_option(options, &["mport", "port-hopping", "port_hopping"]),
    );
    set_optional(
        map,
        "mhop",
        take_option(options, &["mhop", "hop-interval", "hop_interval"]),
    );
    if let Some(obfs) = take_option(options, &["obfs"]) {
        if !matches!(obfs.to_ascii_lowercase().as_str(), "none" | "salamander") {
            return Err("Hysteria obfuscation is unsupported");
        }
        if !obfs.eq_ignore_ascii_case("none") {
            put_str(map, "obfs", obfs);
            set_optional(
                map,
                "obfs-password",
                take_option(options, &["obfs-password"]),
            );
        }
    }
    Ok(())
}

fn apply_quic_common(map: &mut Mapping, options: &mut HashMap<String, String>) {
    set_optional(
        map,
        "congestion-control",
        take_option(options, &["congestion-control", "congestion"]),
    );
    set_optional(map, "alpn", take_option(options, &["alpn"]));
    set_optional(map, "mtu", take_option(options, &["mtu"]));
}

fn take_raw(options: &mut HashMap<String, String>, keys: &[&str]) -> Option<String> {
    let selected = keys.iter().find(|key| options.contains_key(**key)).copied();
    let value = selected.and_then(|key| options.remove(key));
    for key in keys {
        options.remove(*key);
    }
    value
}

fn take_option(options: &mut HashMap<String, String>, keys: &[&str]) -> Option<String> {
    take_raw(options, keys).filter(|value| !value.is_empty())
}

fn take_bool(options: &mut HashMap<String, String>, keys: &[&str]) -> RecordResult<Option<bool>> {
    take_raw(options, keys)
        .map(|value| parse_bool(&value).ok_or("record boolean option is invalid"))
        .transpose()
}

fn take_any_matching(
    options: &mut HashMap<String, String>,
    keys: &[&str],
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let mut matched = false;
    for key in keys {
        if let Some(value) = options.remove(*key) {
            matched |= predicate(&value);
        }
    }
    matched
}

fn take_any_active(options: &mut HashMap<String, String>, keys: &[&str]) -> bool {
    take_any_matching(options, keys, |value| !value.trim().is_empty())
}

fn canonical_type(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ss" | "shadowsocks" => Some("ss"),
        "socks5" | "socks" => Some("socks5"),
        "trojan" => Some("trojan"),
        "vmess" => Some("vmess"),
        "vless" => Some("vless"),
        "hysteria2" | "hy2" => Some("hysteria2"),
        "tuic" => Some("tuic"),
        "juicity" => Some("juicity"),
        "anytls" => Some("anytls"),
        _ => None,
    }
}

fn parse_endpoint(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), parse_port(port)?));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    Some((normalize_host(host), parse_port(port)?))
}

fn parse_port(value: &str) -> Option<u16> {
    let port = value.trim().parse::<u16>().ok()?;
    (port > 0).then_some(port)
}

fn normalize_host(value: &str) -> String {
    value
        .trim()
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value.trim())
        .to_string()
}

fn set_required(map: &mut Mapping, key: &str, value: Option<String>) -> RecordResult<()> {
    let value = value
        .filter(|value| !value.trim().is_empty())
        .ok_or("required record credential is missing")?;
    put_str(map, key, value);
    Ok(())
}

fn set_optional(map: &mut Mapping, key: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        put_str(map, key, value);
    }
}

fn put_str(map: &mut Mapping, key: &str, value: impl Into<String>) {
    map.insert(Value::String(key.to_string()), Value::String(value.into()));
}

fn put_bool(map: &mut Mapping, key: &str, value: bool) {
    map.insert(Value::String(key.to_string()), Value::Bool(value));
}

fn put_u64(map: &mut Mapping, key: &str, value: u64) {
    map.insert(Value::String(key.to_string()), Value::Number(value.into()));
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn looks_like_uuid(value: &str) -> bool {
    value.len() >= 16 && value.bytes().filter(|byte| *byte == b'-').count() >= 2
}

#[cfg(test)]
mod tests;
