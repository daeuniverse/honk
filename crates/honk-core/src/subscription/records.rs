//! Adapters for the comma-separated records emitted by Surge-family clients.
//!
//! Surge, Surfboard and Loon put the display name before the protocol, while
//! Quantumult X puts the protocol before an endpoint. Both normalize to the
//! Clash key vocabulary so the common parser owns Node
//! construction and validation.

use std::collections::HashMap;

use serde_yaml::{Mapping, Value};

use super::Node;

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
        if let Some(record) = parse_record(&fields) {
            records.push(Value::Mapping(record));
        } else {
            tracing::debug!(
                category = "unsupported-record",
                "skipping subscription record"
            );
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

#[derive(Clone, Debug)]
struct Field {
    value: String,
    /// The field began with a quote, so `=` belongs to a positional payload.
    quoted: bool,
    /// A quoted value after `=` may intentionally contain edge spaces.
    quoted_value: bool,
}

/// Split a record on unquoted commas.  Backslash escapes the following byte,
/// which covers the escaped commas and quotes used by these clients.
fn split_fields(line: &str) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quote = None::<char>;
    let mut escaped = false;
    let mut started = false;
    let mut after_quote = false;
    let mut quoted = false;
    let mut quoted_value = false;

    for ch in line.chars() {
        if escaped {
            field.push(ch);
            started = true;
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            if ch == open {
                quote = None;
                after_quote = true;
            } else {
                field.push(ch);
            }
            continue;
        }
        if after_quote && ch.is_whitespace() {
            continue;
        }
        after_quote = false;
        match ch {
            '\'' | '"' => {
                if !started {
                    quoted = true;
                } else if field.contains('=') {
                    quoted_value = true;
                    field.truncate(field.trim_end().len());
                }
                quote = Some(ch);
                started = true;
            }
            ',' => {
                fields.push(Field {
                    value: if quoted || quoted_value {
                        std::mem::take(&mut field)
                    } else {
                        field.trim().to_string()
                    },
                    quoted,
                    quoted_value,
                });
                field.clear();
                started = false;
                after_quote = false;
                quoted = false;
                quoted_value = false;
            }
            _ => {
                if started || !ch.is_whitespace() {
                    field.push(ch);
                }
                if !ch.is_whitespace() {
                    started = true;
                }
            }
        }
    }
    if escaped {
        field.push('\\');
    }
    if quote.is_some() {
        return None;
    }
    fields.push(Field {
        value: if quoted || quoted_value {
            field
        } else {
            field.trim().to_string()
        },
        quoted,
        quoted_value,
    });
    Some(fields)
}

fn parse_record(fields: &[Field]) -> Option<Mapping> {
    let first = fields.first()?.value.trim();
    let (left, right) = first.split_once('=')?;
    if is_qx_type(left.trim()) {
        parse_qx(fields, canonical_type(left.trim())?)
    } else if let Some(protocol) = canonical_type(right.trim()) {
        parse_named(fields, protocol)
    } else {
        None
    }
}

fn parse_named(fields: &[Field], protocol: &'static str) -> Option<Mapping> {
    let (name, _) = fields.first()?.value.split_once('=')?;
    let name = name.trim().to_string();
    let server = normalize_host(fields.get(1)?.value.trim());
    if server.is_empty() {
        return None;
    }
    let port = parse_port(fields.get(2)?.value.trim())?;
    let (positions, options) = positional_options(fields, 3);
    let mut map = base_mapping(protocol, name, server, port);

    if has_chaining(&options) || has_mux(&options) {
        return None;
    }
    if has_reality(&options) && !matches!(protocol, "vless" | "trojan") {
        return None;
    }
    if reality_requested_without_fields(&options) || reality_disabled_with_fields(&options) {
        return None;
    }
    if !apply_named_protocol(&mut map, protocol, &positions, &options) {
        return None;
    }
    Some(map)
}

fn parse_qx(fields: &[Field], protocol: &'static str) -> Option<Mapping> {
    let endpoint = fields.first()?.value.split_once('=')?.1.trim();
    let (server, port) = parse_endpoint(endpoint)?;
    let (_, options) = positional_options(fields, 1);
    let name = options.get("tag").cloned().unwrap_or_default();
    let mut map = base_mapping(protocol, name, server, port);
    if has_chaining(&options) || has_mux(&options) {
        return None;
    }
    if has_reality(&options) && !matches!(protocol, "vless" | "trojan") {
        return None;
    }
    if reality_requested_without_fields(&options) || reality_disabled_with_fields(&options) {
        return None;
    }
    if !apply_qx_protocol(&mut map, protocol, &options) {
        return None;
    }
    Some(map)
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

fn positional_options(fields: &[Field], start: usize) -> (Vec<String>, HashMap<String, String>) {
    let mut positions = Vec::new();
    let mut options = HashMap::new();
    for field in fields.iter().skip(start) {
        if !field.quoted
            && let Some((key, value)) = field.value.split_once('=')
            && is_option_key(key)
        {
            let value = if field.quoted_value {
                value.to_string()
            } else {
                value.trim().to_string()
            };
            options.insert(key.trim().to_ascii_lowercase(), value);
        } else if !field.value.trim().is_empty() {
            // A quoted field is positional even when its payload contains '='.
            positions.push(if field.quoted {
                field.value.clone()
            } else {
                field.value.trim().to_string()
            });
        }
    }
    (positions, options)
}

fn is_option_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "alpn"
            | "allow-insecure"
            | "auth"
            | "chain"
            | "chained"
            | "cipher"
            | "congestion"
            | "congestion-control"
            | "dialer-proxy"
            | "dialer_proxy"
            | "download-bandwidth"
            | "down-mbps"
            | "downmbps"
            | "encrypt-method"
            | "encryption"
            | "flow"
            | "fast-open"
            | "grpc-service"
            | "grpc-service-name"
            | "hop-interval"
            | "hop_interval"
            | "host"
            | "insecure"
            | "mhop"
            | "mport"
            | "mtu"
            | "method"
            | "mux"
            | "network"
            | "obfs"
            | "obfs-host"
            | "obfs-password"
            | "obfs-uri"
            | "over-tls"
            | "packet-addr"
            | "packet_addr"
            | "packet-encoding"
            | "packet_encoding"
            | "packetaddr"
            | "packetencoding"
            | "password"
            | "path"
            | "plugin"
            | "plugin-opts"
            | "plugin_opts"
            | "port-hopping"
            | "port_hopping"
            | "proxy"
            | "proxy-policy"
            | "proxy_policy"
            | "public-key"
            | "reality-base64-pubkey"
            | "reality-hex-shortid"
            | "reality-public-key"
            | "reality-short-id"
            | "security"
            | "server-name"
            | "servername"
            | "service-name"
            | "short-id"
            | "skip-cert-verify"
            | "sni"
            | "spider-x"
            | "spx"
            | "tag"
            | "tls"
            | "tls-host"
            | "tls-name"
            | "tls-verification"
            | "transport"
            | "udp"
            | "udp-relay"
            | "underlying-proxy"
            | "underlying_proxy"
            | "upload-bandwidth"
            | "up-mbps"
            | "upmbps"
            | "username"
            | "uuid"
            | "vless-flow"
            | "ws"
            | "ws-headers"
            | "ws-host"
            | "ws-path"
    )
}

fn apply_named_protocol(
    map: &mut Mapping,
    protocol: &str,
    positions: &[String],
    options: &HashMap<String, String>,
) -> bool {
    match protocol {
        "ss" => {
            let cipher = option(options, &["encrypt-method", "method", "cipher"])
                .or_else(|| positions.first().cloned());
            let password = option(options, &["password"]).or_else(|| positions.get(1).cloned());
            if !set_required(map, "cipher", cipher) || !set_required(map, "password", password) {
                return false;
            }
            if [
                "plugin",
                "plugin-opts",
                "plugin_opts",
                "obfs",
                "tls",
                "over-tls",
                "security",
            ]
            .into_iter()
            .any(|key| {
                options
                    .get(key)
                    .is_some_and(|value| !value.trim().is_empty())
            }) {
                return false;
            }
        }
        "socks5" => {
            let username = option(options, &["username"]).or_else(|| positions.first().cloned());
            let password = option(options, &["password"]).or_else(|| positions.get(1).cloned());
            set_optional(map, "username", username);
            set_optional(map, "password", password);
            if options
                .get("tls")
                .is_some_and(|value| parse_bool(value).is_none_or(|enabled| enabled))
                || options
                    .get("over-tls")
                    .is_some_and(|value| parse_bool(value).is_none_or(|enabled| enabled))
            {
                return false;
            }
        }
        "vmess" => {
            let uuid = option(options, &["username", "uuid", "password"])
                .or_else(|| {
                    positions
                        .iter()
                        .find(|value| looks_like_uuid(value))
                        .cloned()
                })
                .or_else(|| positions.get(1).cloned());
            if !set_required(map, "uuid", uuid) {
                return false;
            }
            set_optional(
                map,
                "cipher",
                option(options, &["method", "encryption", "cipher"])
                    .or_else(|| positions.first().filter(|v| !looks_like_uuid(v)).cloned()),
            );
            if !apply_transport(map, options, positions) || !apply_tls(map, protocol, options) {
                return false;
            }
        }
        "trojan" => {
            let password = option(options, &["password"]).or_else(|| positions.first().cloned());
            if !set_required(map, "password", password) {
                return false;
            }
            put_bool(map, "tls", true);
            if !apply_transport(map, options, positions)
                || !apply_tls(map, protocol, options)
                || !apply_reality(map, options)
            {
                return false;
            }
        }
        "vless" => {
            let uuid =
                option(options, &["uuid", "password"]).or_else(|| positions.first().cloned());
            if !set_required(map, "uuid", uuid) {
                return false;
            }
            set_optional(map, "flow", option(options, &["flow", "vless-flow"]));
            if !apply_transport(map, options, positions)
                || !apply_tls(map, protocol, options)
                || !apply_vless_mode(map, options)
                || !apply_reality(map, options)
            {
                return false;
            }
        }
        "hysteria2" => {
            set_optional(
                map,
                "auth",
                option(options, &["password", "auth"]).or_else(|| positions.first().cloned()),
            );
            put_bool(map, "tls", true);
            if !apply_tls(map, protocol, options) || !apply_hysteria(map, options) {
                return false;
            }
            apply_quic_common(map, options);
        }
        "tuic" => {
            let uuid =
                option(options, &["uuid", "username"]).or_else(|| positions.first().cloned());
            let password = option(options, &["password"]).or_else(|| positions.get(1).cloned());
            if !set_required(map, "uuid", uuid) || !set_required(map, "password", password) {
                return false;
            }
            put_bool(map, "tls", true);
            if !apply_tls(map, protocol, options) {
                return false;
            }
            apply_quic_common(map, options);
        }
        "anytls" => {
            let password = option(options, &["password"]).or_else(|| positions.first().cloned());
            if !set_required(map, "password", password) {
                return false;
            }
            put_bool(map, "tls", true);
            set_optional(map, "network", option(options, &["network"]));
            if !apply_tls(map, protocol, options) {
                return false;
            }
        }
        _ => return false,
    }
    true
}

fn apply_qx_protocol(map: &mut Mapping, protocol: &str, options: &HashMap<String, String>) -> bool {
    match protocol {
        "ss" => {
            if !set_required(
                map,
                "cipher",
                option(options, &["method", "cipher", "encrypt-method"]),
            ) || !set_required(map, "password", option(options, &["password"]))
            {
                return false;
            }
            if options
                .get("obfs")
                .is_some_and(|value| !value.trim().is_empty() && value != "none")
                || [
                    "tls",
                    "over-tls",
                    "network",
                    "transport",
                    "tls-host",
                    "tls-verification",
                ]
                .into_iter()
                .any(|key| {
                    options
                        .get(key)
                        .is_some_and(|value| !value.trim().is_empty())
                })
            {
                return false;
            }
        }
        "socks5" => {
            set_optional(map, "username", option(options, &["username"]));
            set_optional(map, "password", option(options, &["password"]));
            if [
                "obfs",
                "network",
                "transport",
                "tls",
                "over-tls",
                "tls-host",
                "tls-verification",
            ]
            .into_iter()
            .any(|key| {
                options
                    .get(key)
                    .is_some_and(|value| !value.trim().is_empty())
            }) {
                return false;
            }
        }
        "vmess" => {
            if !set_required(
                map,
                "uuid",
                option(options, &["password", "uuid", "username"]),
            ) {
                return false;
            }
            set_optional(map, "cipher", option(options, &["method", "cipher"]));
            if !apply_qx_obfs(map, options, false) || !apply_tls(map, protocol, options) {
                return false;
            }
        }
        "trojan" => {
            if !set_required(map, "password", option(options, &["password"])) {
                return false;
            }
            put_bool(map, "tls", true);
            if !apply_qx_obfs(map, options, true) || !apply_tls(map, protocol, options) {
                return false;
            }
            if !apply_qx_reality(map, options) {
                return false;
            }
        }
        "vless" => {
            if !set_required(map, "uuid", option(options, &["password", "uuid"])) {
                return false;
            }
            set_optional(
                map,
                "encryption",
                option(options, &["method", "encryption"]),
            );
            set_optional(map, "flow", option(options, &["vless-flow", "flow"]));
            if !apply_qx_obfs(map, options, false) || !apply_tls(map, protocol, options) {
                return false;
            }
            if !apply_qx_reality(map, options) || !apply_vless_mode(map, options) {
                return false;
            }
            if let Some(value) = options.get("udp-relay") {
                let Some(enabled) = parse_bool(value) else {
                    return false;
                };
                if enabled {
                    put_bool(map, "udp", true);
                }
            }
        }
        "hysteria2" => {
            set_optional(map, "auth", option(options, &["password", "auth"]));
            put_bool(map, "tls", true);
            if !apply_tls(map, protocol, options) || !apply_hysteria(map, options) {
                return false;
            }
            apply_quic_common(map, options);
        }
        "tuic" => {
            if !set_required(map, "uuid", option(options, &["uuid", "username"]))
                || !set_required(map, "password", option(options, &["password"]))
            {
                return false;
            }
            put_bool(map, "tls", true);
            if !apply_tls(map, protocol, options) {
                return false;
            }
            apply_quic_common(map, options);
        }
        "anytls" => {
            if !set_required(map, "password", option(options, &["password"])) {
                return false;
            }
            put_bool(map, "tls", true);
            set_optional(map, "network", option(options, &["network"]));
            if !apply_tls(map, protocol, options) {
                return false;
            }
        }
        _ => return false,
    }
    true
}

fn apply_transport(
    map: &mut Mapping,
    options: &HashMap<String, String>,
    positions: &[String],
) -> bool {
    if option(options, &["obfs"])
        .is_some_and(|value| !matches!(value.as_str(), "" | "none" | "tcp"))
    {
        return false;
    }
    let mut transport = option(options, &["transport", "network"]);
    if transport.is_none() {
        if let Some(value) = options.get("ws") {
            let Some(enabled) = parse_bool(value) else {
                return false;
            };
            if enabled {
                transport = Some("ws".to_string());
            }
        }
    }
    let transport = transport.or_else(|| {
        positions
            .iter()
            .find(|value| matches!(value.as_str(), "tcp" | "ws" | "grpc" | "h2" | "httpupgrade"))
            .cloned()
    });
    if transport.is_none()
        && [
            "ws-path",
            "ws-host",
            "ws-headers",
            "grpc-service-name",
            "grpc-service",
        ]
        .into_iter()
        .any(|key| {
            options
                .get(key)
                .is_some_and(|value| !value.trim().is_empty())
        })
    {
        return false;
    }
    if let Some(transport) = transport {
        let transport = transport.to_ascii_lowercase();
        if !matches!(transport.as_str(), "tcp" | "ws" | "grpc") {
            return false;
        }
        put_str(map, "network", transport.clone());
        if transport == "ws" {
            set_optional(
                map,
                "ws-path",
                option(options, &["ws-path", "path", "obfs-uri"]),
            );
            set_optional(
                map,
                "ws-host",
                option(options, &["ws-host", "host", "obfs-host"]),
            );
            if let Some(headers) = option(options, &["ws-headers"]) {
                if let Some(host) = headers
                    .split_once(':')
                    .filter(|(key, _)| key.trim().eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value.trim().to_string())
                {
                    put_str(map, "ws-host", host);
                } else {
                    return false;
                }
            }
        }
        if transport == "grpc" {
            set_optional(
                map,
                "grpc-service",
                option(
                    options,
                    &["grpc-service-name", "grpc-service", "service-name"],
                ),
            );
        }
    }
    true
}

fn apply_qx_obfs(map: &mut Mapping, options: &HashMap<String, String>, default_tls: bool) -> bool {
    let Some(obfs) = option(options, &["obfs"]) else {
        if default_tls {
            put_bool(map, "tls", true);
        }
        return true;
    };
    match obfs.to_ascii_lowercase().as_str() {
        "none" | "tcp" => {
            if default_tls {
                put_bool(map, "tls", true);
            }
        }
        "ws" => {
            put_str(map, "network", "ws");
            put_bool(map, "tls", false);
            set_optional(map, "ws-path", option(options, &["obfs-uri", "path"]));
            set_optional(map, "ws-host", option(options, &["obfs-host", "host"]));
        }
        "wss" => {
            put_str(map, "network", "ws");
            put_bool(map, "tls", true);
            set_optional(map, "ws-path", option(options, &["obfs-uri", "path"]));
            set_optional(map, "ws-host", option(options, &["obfs-host", "host"]));
            set_optional(map, "servername", option(options, &["obfs-host", "host"]));
        }
        "over-tls" => {
            put_str(map, "network", "tcp");
            put_bool(map, "tls", true);
            set_optional(map, "servername", option(options, &["obfs-host", "host"]));
        }
        _ => return false,
    }
    true
}

fn apply_tls(map: &mut Mapping, protocol: &str, options: &HashMap<String, String>) -> bool {
    let tls = match option(options, &["tls"]) {
        Some(value) => match parse_bool(&value) {
            Some(value) => Some(value),
            None => return false,
        },
        None => None,
    };
    let over_tls = match option(options, &["over-tls"]) {
        Some(value) => match parse_bool(&value) {
            Some(value) => Some(value),
            None => return false,
        },
        None => None,
    };
    if tls.is_some() && over_tls.is_some() && tls != over_tls {
        return false;
    }
    if let Some(enabled) = over_tls.or(tls) {
        put_bool(map, "tls", enabled);
    }

    if let Some(value) = option(options, &["skip-cert-verify", "allow-insecure", "insecure"]) {
        let Some(skip) = parse_bool(&value) else {
            return false;
        };
        put_bool(map, "skip-cert-verify", skip);
    }
    if let Some(value) = option(options, &["tls-verification"]) {
        let Some(verify) = parse_bool(&value) else {
            return false;
        };
        put_bool(map, "skip-cert-verify", !verify);
    }
    set_optional(
        map,
        "servername",
        option(options, &["servername", "sni", "tls-name", "tls-host"]),
    );
    if protocol == "vless" {
        if let Some(value) = option(options, &["security"]) {
            if !matches!(value.as_str(), "none" | "tls" | "reality") {
                return false;
            }
            if value == "none" {
                put_bool(map, "tls", false);
            } else {
                put_bool(map, "tls", true);
            }
        }
    }
    true
}

fn apply_vless_mode(map: &mut Mapping, options: &HashMap<String, String>) -> bool {
    for key in ["packet-addr", "packet_addr", "packetaddr"] {
        if let Some(value) = options.get(key) {
            let Some(enabled) = parse_bool(value) else {
                return false;
            };
            if enabled {
                return false;
            }
        }
    }
    if let Some(value) = option(
        options,
        &["packet-encoding", "packet_encoding", "packetencoding"],
    ) {
        if !matches!(value.as_str(), "" | "none" | "xudp") {
            return false;
        }
        if value == "xudp" {
            put_str(map, "packet-encoding", "xudp");
        }
    }
    if let Some(value) = option(options, &["udp"]) {
        let Some(enabled) = parse_bool(&value) else {
            return false;
        };
        put_bool(map, "udp", enabled);
    }
    true
}

fn apply_reality(map: &mut Mapping, options: &HashMap<String, String>) -> bool {
    let public_key = option(options, &["public-key", "reality-public-key"]);
    let short_id = option(options, &["short-id", "reality-short-id"]);
    if public_key.is_none() && short_id.is_none() {
        return true;
    }
    let mut reality = Mapping::new();
    if let Some(value) = public_key {
        put_str(&mut reality, "public-key", value);
    }
    if let Some(value) = short_id {
        put_str(&mut reality, "short-id", value);
    }
    if let Some(value) = option(options, &["spider-x", "spx"]) {
        put_str(&mut reality, "spider-x", value);
    }
    map.insert(
        Value::String("reality-opts".to_string()),
        Value::Mapping(reality),
    );
    put_bool(map, "tls", true);
    true
}

fn apply_qx_reality(map: &mut Mapping, options: &HashMap<String, String>) -> bool {
    let public_key = option(options, &["reality-base64-pubkey", "reality-public-key"]);
    let short_id = option(options, &["reality-hex-shortid", "reality-short-id"]);
    if public_key.is_none() && short_id.is_none() {
        return true;
    }
    let mut reality = Mapping::new();
    if let Some(value) = public_key {
        put_str(&mut reality, "public-key", value);
    }
    if let Some(value) = short_id {
        put_str(&mut reality, "short-id", value);
    }
    map.insert(
        Value::String("reality-opts".to_string()),
        Value::Mapping(reality),
    );
    put_bool(map, "tls", true);
    true
}

fn apply_hysteria(map: &mut Mapping, options: &HashMap<String, String>) -> bool {
    set_optional(
        map,
        "upload-bandwidth",
        option(options, &["upload-bandwidth", "up-mbps", "upmbps"]),
    );
    set_optional(
        map,
        "download-bandwidth",
        option(options, &["download-bandwidth", "down-mbps", "downmbps"]),
    );
    set_optional(
        map,
        "mport",
        option(options, &["mport", "port-hopping", "port_hopping"]),
    );
    set_optional(
        map,
        "mhop",
        option(options, &["mhop", "hop-interval", "hop_interval"]),
    );
    if let Some(obfs) = option(options, &["obfs"]) {
        if !matches!(
            obfs.to_ascii_lowercase().as_str(),
            "" | "none" | "salamander"
        ) {
            return false;
        }
        if !obfs.is_empty() && obfs != "none" {
            put_str(map, "obfs", obfs);
            set_optional(map, "obfs-password", option(options, &["obfs-password"]));
        }
    }
    true
}

fn apply_quic_common(map: &mut Mapping, options: &HashMap<String, String>) {
    set_optional(
        map,
        "congestion-control",
        option(options, &["congestion-control", "congestion"]),
    );
    set_optional(map, "alpn", option(options, &["alpn"]));
    set_optional(map, "mtu", option(options, &["mtu"]));
}

fn has_reality(options: &HashMap<String, String>) -> bool {
    [
        "public-key",
        "short-id",
        "reality-public-key",
        "reality-short-id",
        "reality-base64-pubkey",
        "reality-hex-shortid",
        "spider-x",
        "spx",
    ]
    .into_iter()
    .any(|key| {
        options
            .get(key)
            .is_some_and(|value| !value.trim().is_empty())
    })
}

fn reality_requested_without_fields(options: &HashMap<String, String>) -> bool {
    options
        .get("security")
        .is_some_and(|value| value.eq_ignore_ascii_case("reality"))
        && !has_reality(options)
}

fn reality_disabled_with_fields(options: &HashMap<String, String>) -> bool {
    options
        .get("security")
        .is_some_and(|value| value.eq_ignore_ascii_case("none"))
        && has_reality(options)
}

fn has_chaining(options: &HashMap<String, String>) -> bool {
    [
        "proxy",
        "underlying-proxy",
        "underlying_proxy",
        "dialer-proxy",
        "dialer_proxy",
        "chain",
        "chained",
        "proxy-policy",
        "proxy_policy",
    ]
    .into_iter()
    .any(|key| {
        options
            .get(key)
            .is_some_and(|value| !value.trim().is_empty())
    })
}

fn has_mux(options: &HashMap<String, String>) -> bool {
    options.get("mux").is_some_and(|value| {
        parse_bool(value).unwrap_or_else(|| !value.eq_ignore_ascii_case("none"))
    })
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
        "anytls" => Some("anytls"),
        _ => None,
    }
}

fn is_qx_type(value: &str) -> bool {
    canonical_type(value).is_some()
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

fn option(options: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| options.get(*key))
        .cloned()
        .filter(|value| !value.is_empty())
}

fn set_required(map: &mut Mapping, key: &str, value: Option<String>) -> bool {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return false;
    };
    put_str(map, key, value);
    true
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
mod tests {
    use super::*;

    #[test]
    fn tokenizer_preserves_quoted_commas_and_escaped_quotes() {
        let fields =
            split_fields(r#""name, east"=ss,example.com,443,"aes-128-gcm","pa\"ss,word""#).unwrap();
        assert_eq!(fields[0].value, "name, east=ss");
        assert_eq!(fields[3].value, "aes-128-gcm");
        assert_eq!(fields[4].value, "pa\"ss,word");
    }

    #[test]
    fn quoted_positional_password_keeps_equals_and_edge_spaces() {
        let node =
            parse_records_subscription(r#"node=trojan, example.com, 443, " pass,word = " "#, None)
                .unwrap()
                .remove(0);
        assert_eq!(
            node.trojan().unwrap().password.as_deref(),
            Some(" pass,word = ")
        );
        let node = parse_records_subscription(
            r#"node=trojan, example.com, 443, password = " pass,word = " "#,
            None,
        )
        .unwrap()
        .remove(0);
        assert_eq!(
            node.trojan().unwrap().password.as_deref(),
            Some(" pass,word = ")
        );
    }

    #[test]
    fn qx_endpoint_parser_handles_bracketed_ipv6() {
        assert_eq!(
            parse_endpoint("[2001:db8::1]:443"),
            Some(("2001:db8::1".into(), 443))
        );
        assert!(parse_endpoint("2001:db8::1:443").is_none());
    }

    #[test]
    fn qx_reality_fields_are_normalized_without_leaking_record_text() {
        let fields = split_fields(
            "vless=[2001:db8::1]:443,method=none,password=uuid,obfs=over-tls,reality-base64-pubkey=key,reality-hex-shortid=sid,vless-flow=xtls-rprx-vision,tag=quoted",
        )
        .unwrap();
        let map = parse_record(&fields).unwrap();
        assert_eq!(map.get("type").and_then(Value::as_str), Some("vless"));
        assert_eq!(
            map.get("server").and_then(Value::as_str),
            Some("2001:db8::1")
        );
        assert_eq!(map.get("name").and_then(Value::as_str), Some("quoted"));
        assert!(map.get("reality-opts").is_some());
        assert_eq!(
            map.get("flow").and_then(Value::as_str),
            Some("xtls-rprx-vision")
        );
    }

    #[test]
    fn unsupported_transport_is_rejected_without_tcp_fallback() {
        let fields =
            split_fields("node=vless,example.com,443,uuid,transport=h2,over-tls=true").unwrap();
        assert!(parse_record(&fields).is_none());
    }
}
