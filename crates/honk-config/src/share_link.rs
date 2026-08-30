//! Share-link parsing: build a [`Node`] from a proxy share URI.
//!
//! Supports the common `scheme://` share-link formats (socks5, ss,
//! trojan, anytls, vmess, vless, hysteria2, tuic, juicity).
//! Shadowsocks links follow SIP002: the userinfo is either
//! `base64(method:password)` or plain `method:password` (the method itself
//! may still be base64-encoded), the whole `method:password@host:port`
//! authority may also be base64-encoded, and an optional `/?plugin=...`
//! query suffix carries the plugin name and options.
//!
//! `vmess://<base64>` does not follow the URL-shaped layout and is decoded
//! before the generic URL path: the payload is base64 (URL-safe or standard
//! alphabet) of a JSON object with the v2rayN field set (`add`, `port`,
//! `id`, `scy`, `net`, `host`, `path`, `tls`, `sni`, ...).
//!
//! This is the single share-link parser for the whole workspace: the dae
//! config parser and the core subscription fetcher both delegate to
//! [`Node::from_share_link`].

use std::borrow::Cow;
use std::collections::HashMap;

use base64::Engine as _;

use crate::error::ConfigError;
use crate::node::Node;
use crate::types::{NodeProtocol, parse_duration_secs};

impl Node {
    /// Parse a proxy share link (e.g. `ss://...`, `trojan://...`) into a [`Node`].
    /// A chain describes several hops; only the first is parsed.
    pub fn from_share_link(link: &str) -> Result<Node, ConfigError> {
        let first = link.split("->").next().unwrap_or("").trim();
        if let Some(payload) = first.strip_prefix("vmess://") {
            return parse_vmess_link(payload);
        }

        let decoded_ss;
        let first = match first.strip_prefix("ss://") {
            Some(rest) => match decode_full_base64_ss_link(rest) {
                Some(rebuilt) => {
                    decoded_ss = rebuilt;
                    decoded_ss.as_str()
                }
                None => first,
            },
            None => first,
        };
        let (first, embedded_hop_ports) = extract_hy2_hop_ports(first)?;
        let url = url::Url::parse(first.as_ref())
            .map_err(|_| ConfigError::Parse("invalid share link syntax".into()))?;
        let scheme = url.scheme();
        let protocol = match scheme {
            "socks5" | "socks4" | "socks4a" => NodeProtocol::Socks5,
            "ss" => NodeProtocol::SS,
            "trojan" => NodeProtocol::Trojan,
            "anytls" => NodeProtocol::AnyTLS,
            "vmess" => NodeProtocol::VMess,
            "vless" => NodeProtocol::VLess,
            "hysteria2" | "hysteria" => NodeProtocol::Hysteria2,
            "tuic" => NodeProtocol::Tuic,
            "juicity" => NodeProtocol::Juicity,
            _ => return Err(ConfigError::UnknownProtocol(scheme.to_string())),
        };
        let host = url
            .host_str()
            .ok_or_else(|| ConfigError::Parse("missing host in share link".into()))?
            .to_string();
        let port = url.port().unwrap_or(443);
        let outbound = match protocol {
            NodeProtocol::SS => crate::node::OutboundConfig::Shadowsocks(Default::default()),
            NodeProtocol::Trojan => crate::node::OutboundConfig::Trojan(Default::default()),
            NodeProtocol::VMess => crate::node::OutboundConfig::Vmess(Default::default()),
            NodeProtocol::VLess => crate::node::OutboundConfig::Vless(Default::default()),
            NodeProtocol::Socks5 => crate::node::OutboundConfig::Socks5(Default::default()),
            NodeProtocol::Hysteria2 => crate::node::OutboundConfig::Hysteria2(Default::default()),
            NodeProtocol::Tuic => crate::node::OutboundConfig::Tuic(Default::default()),
            NodeProtocol::Juicity => crate::node::OutboundConfig::Juicity(Default::default()),
            NodeProtocol::AnyTLS => crate::node::OutboundConfig::AnyTls(Default::default()),
            NodeProtocol::Direct | NodeProtocol::Block => unreachable!(),
        };
        let mut node = Node {
            host: host.clone(),
            address: format!("{}:{}", host, port),
            port,
            outbound,
            ..Default::default()
        };

        if let Some(config) = node.shadowsocks_mut() {
            apply_ss_userinfo(config, &url);
        } else {
            let username = (!url.username().is_empty()).then(|| percent_decode_str(url.username()));
            let password = url.password().map(percent_decode_str);
            match &mut node.outbound {
                crate::node::OutboundConfig::Socks5(config) => {
                    config.username = username;
                    config.password = password;
                }
                crate::node::OutboundConfig::Trojan(config) => {
                    config.password = password.or(username);
                }
                crate::node::OutboundConfig::Vless(config) => {
                    config.uuid = password.or(username);
                }
                crate::node::OutboundConfig::Hysteria2(config) => {
                    config.auth = username.or(password);
                }
                crate::node::OutboundConfig::Tuic(config) => {
                    config.uuid = username;
                    config.password = password;
                }
                crate::node::OutboundConfig::Juicity(config) => {
                    config.uuid = username;
                    config.password = password;
                }
                crate::node::OutboundConfig::AnyTls(config) => {
                    config.password = password.or(username);
                }
                crate::node::OutboundConfig::Vmess(_)
                | crate::node::OutboundConfig::Shadowsocks(_)
                | crate::node::OutboundConfig::Direct
                | crate::node::OutboundConfig::Block => {}
            }
        }

        node.name = url
            .fragment()
            .map(percent_decode_str)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("{}-{}", scheme, host));

        let mut query = HashMap::new();
        let mut mode_seen = false;
        for (key, value) in url.query_pairs() {
            let key = key.into_owned();
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

        if let Some(tls) = node.tls_mut() {
            tls.enabled = match protocol {
                NodeProtocol::Trojan | NodeProtocol::AnyTLS => true,
                NodeProtocol::VLess | NodeProtocol::VMess => {
                    match query.get("security").map(String::as_str) {
                        Some("none") => false,
                        Some(_) => true,
                        None => protocol == NodeProtocol::VLess,
                    }
                }
                _ => tls.enabled,
            };
            tls.sni = query.get("sni").cloned();
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
        }

        if let Some(transport) = node.transport_mut() {
            if let Some(value) = query.get("type").or_else(|| query.get("network")) {
                transport.transport = value.clone();
            }
            let mut host_consumed = false;
            match transport.transport.as_str() {
                "ws" => {
                    if let Some(value) = query.get("host") {
                        transport.ws_host = Some(value.clone());
                        host_consumed = true;
                    }
                    transport.ws_path = query.get("path").cloned();
                }
                "grpc" => {
                    transport.grpc_service = query
                        .get("serviceName")
                        .or_else(|| query.get("service_name"))
                        .cloned();
                }
                _ => {}
            }
            if !host_consumed
                && node.tls().is_some_and(|tls| tls.sni.is_none())
                && let Some(value) = query.get("host")
                && let Some(tls) = node.tls_mut()
            {
                tls.sni = Some(value.clone());
            }
        } else if node.tls().is_some_and(|tls| tls.sni.is_none())
            && let Some(value) = query.get("host")
            && let Some(tls) = node.tls_mut()
        {
            tls.sni = Some(value.clone());
        }

        if let Some(value) = query.get("plugin") {
            let Some(config) = node.shadowsocks_mut() else {
                return Err(ConfigError::Parse(
                    "plugin parameters are valid only for Shadowsocks links".into(),
                ));
            };
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
            let Some(config) = node.shadowsocks_mut() else {
                return Err(ConfigError::Parse(
                    "plugin parameters are valid only for Shadowsocks links".into(),
                ));
            };
            config.plugin_opts = Some(value.clone());
        }

        if let Some(config) = node.hysteria2_mut() {
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
        }

        if matches!(
            protocol,
            NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity
        ) && let Some(mtu) = query
            .get("mtu")
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|mtu| (1200..=65527).contains(mtu))
        {
            match &mut node.outbound {
                crate::node::OutboundConfig::Hysteria2(config) => config.quic.mtu = Some(mtu),
                crate::node::OutboundConfig::Tuic(config) => config.quic.mtu = Some(mtu),
                crate::node::OutboundConfig::Juicity(config) => config.quic.mtu = Some(mtu),
                _ => unreachable!(),
            }
        }

        if let Some(config) = node.tuic_mut() {
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
        }

        if let Some(config) = node.anytls_mut() {
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

        if let Some(config) = node.vless_mut() {
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
            if query
                .get("security")
                .is_some_and(|value| value == "reality")
            {
                config.tls.enabled = true;
                config.tls.reality_public_key = query.get("pbk").cloned();
                config.tls.reality_short_id = query.get("sid").cloned();
                config.tls.reality_spider_x = Some(
                    query
                        .get("spx")
                        .filter(|value| !value.is_empty())
                        .cloned()
                        .unwrap_or_else(|| "/".to_string()),
                );
            }
            config.flow = query.get("flow").cloned();
            config.encryption = query
                .get("encryption")
                .filter(|value| !value.trim().is_empty())
                .cloned();
        }

        node.validate_protocol()?;
        node.id = node.derive_id();
        Ok(node)
    }
}

/// Parse a `vmess://` share link: base64 of a JSON object (v2rayN schema).
fn parse_vmess_link(payload: &str) -> Result<Node, ConfigError> {
    let raw = base64_decode_flexible(payload)
        .ok_or_else(|| ConfigError::Parse("invalid vmess link: base64 decode failed".into()))?;
    let text = String::from_utf8(raw)
        .map_err(|_| ConfigError::Parse("invalid vmess link: payload is not UTF-8".into()))?;
    let json: VmessLinkJson = serde_json::from_str(&text)
        .map_err(|_| ConfigError::Parse("invalid vmess link JSON".into()))?;
    json.into_node()
}

/// Field set of a base64-JSON `vmess://` share link (v2rayN schema).
///
/// `port`/`aid` are modelled as [`serde_json::Value`] because exporters
/// disagree on quoting them.
#[derive(serde::Deserialize)]
struct VmessLinkJson {
    /// Remark / display name.
    ps: Option<String>,
    /// Server host.
    add: Option<String>,
    /// Server port (string or number).
    port: Option<serde_json::Value>,
    /// User UUID.
    id: Option<String>,
    /// AlterId — accepted for compatibility; AEAD (alterId=0) is assumed.
    #[allow(dead_code)]
    aid: Option<serde_json::Value>,
    /// Cipher (`scy` in newer links, `security` in older ones).
    scy: Option<String>,
    security: Option<String>,
    /// Transport: tcp / ws / grpc / h2 / kcp.
    net: Option<String>,
    /// Transport header type; accepted for compatibility, not stored.
    #[allow(dead_code)]
    r#type: Option<String>,
    /// WS host header on `net = "ws"` links, TLS SNI elsewhere.
    host: Option<String>,
    /// WS path, or gRPC service name on `net = "grpc"` links.
    path: Option<String>,
    /// TLS flag: the exact string "tls" enables it.
    tls: Option<String>,
    /// Explicit TLS SNI (takes precedence over `host`).
    sni: Option<String>,
    /// ALPN; accepted for compatibility, not stored.
    #[allow(dead_code)]
    alpn: Option<String>,
}

impl VmessLinkJson {
    fn into_node(self) -> Result<Node, ConfigError> {
        let host = self.add.filter(|h| !h.is_empty()).ok_or_else(|| {
            ConfigError::Parse("invalid vmess link: missing server address".into())
        })?;
        let port = json_port(self.port)
            .ok_or_else(|| ConfigError::Parse("invalid vmess link: missing or bad port".into()))?;
        let id = self
            .id
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ConfigError::Parse("invalid vmess link: missing user id".into()))?;

        let transport = self.net.unwrap_or_default();

        let mut stream = crate::node::StreamTransportOptions {
            transport: transport.clone(),
            ..Default::default()
        };
        let mut tls = crate::node::TlsOptions {
            enabled: self.tls.as_deref() == Some("tls"),
            ..Default::default()
        };
        if let Some(value) = self.host.filter(|value| !value.is_empty()) {
            if transport == "ws" {
                stream.ws_host = Some(value);
            } else {
                tls.sni = Some(value);
            }
        }
        if let Some(value) = self.sni.filter(|value| !value.is_empty()) {
            tls.sni = Some(value);
        }
        if let Some(value) = self.path.filter(|value| !value.is_empty()) {
            match transport.as_str() {
                "ws" => stream.ws_path = Some(value),
                "grpc" => stream.grpc_service = Some(value),
                _ => {}
            }
        }
        let mut node = Node {
            host: host.clone(),
            address: format!("{}:{}", host, port),
            port,
            name: self.ps.unwrap_or_else(|| format!("vmess-{}", host)),
            outbound: crate::node::OutboundConfig::Vmess(crate::node::VmessConfig {
                uuid: Some(id),
                encryption: self.scy.or(self.security),
                network: (!transport.is_empty()).then_some(transport),
                transport: stream,
                tls,
            }),
            ..Default::default()
        };
        node.id = node.derive_id();
        Ok(node)
    }
}

/// Extract a port from a JSON value that may be a string or a number.
fn json_port(value: Option<serde_json::Value>) -> Option<u16> {
    match value? {
        serde_json::Value::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Apply SIP002 userinfo decoding for Shadowsocks links.
///
/// The userinfo is `base64(method:password)` or plain `method:password`; the
/// decoded method lands in `encryption` and the password in `password`.
/// Note: the `url` crate percent-encodes `=` in userinfo, so the raw parts
/// are percent-decoded before any base64 decoding happens.
fn apply_ss_userinfo(config: &mut crate::node::ShadowsocksConfig, url: &url::Url) {
    let userinfo = match url.password() {
        Some(pw) => format!(
            "{}:{}",
            percent_decode_str(url.username()),
            percent_decode_str(pw)
        ),
        None => percent_decode_str(url.username()),
    };
    if userinfo.is_empty() {
        return;
    }

    match decode_ss_userinfo(&userinfo) {
        Some((method, password)) => {
            config.encryption = Some(method);
            config.password = Some(password);
        }
        None => {
            // Unrecognized userinfo: keep it as the password so nothing is lost.
            config.password = Some(userinfo);
        }
    }
}

/// Decode a SIP002 userinfo string into `(method, password)`.
fn decode_ss_userinfo(userinfo: &str) -> Option<(String, String)> {
    if let Some((method, password)) = userinfo.split_once(':') {
        return Some((decode_ss_method(method), password.to_string()));
    }
    // Whole userinfo is base64(method:password).
    let decoded = base64_decode_flexible(userinfo)?;
    let text = String::from_utf8(decoded).ok()?;
    let (method, password) = text.split_once(':')?;
    Some((decode_ss_method(method), password.to_string()))
}

/// Decode a possibly base64-encoded cipher name.
///
/// Plain cipher names are returned unchanged; values that are not plausible
/// cipher names are base64-decoded when the result looks like one.
fn decode_ss_method(method: &str) -> String {
    if looks_like_cipher(method) {
        return method.to_string();
    }
    if let Some(decoded) = base64_decode_flexible(method)
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| looks_like_cipher(s))
    {
        return decoded;
    }
    method.to_string()
}

/// Heuristic: does this string look like a Shadowsocks cipher name?
fn looks_like_cipher(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && (s.contains('-') || matches!(s, "salsa20" | "chacha20" | "rc4"))
}

/// Decode the SIP002 full-base64 form `ss://base64(method:password@host:port)`,
/// keeping any `?query` / `#fragment` suffix, and return the rebuilt link.
/// Returns `None` for the (more common) forms that already carry an `@`.
fn decode_full_base64_ss_link(rest: &str) -> Option<String> {
    let end = rest.find(['?', '#', '/']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let text = String::from_utf8(base64_decode_flexible(authority)?).ok()?;
    if !text.contains('@') {
        return None;
    }
    Some(format!("ss://{}{}", text, &rest[end..]))
}

/// Split official-style hop ports out of a hysteria2 authority
/// (`hysteria2://auth@host:443,5000-6000/...`). The whole list is the hop
/// set; the first entry stays in the rebuilt address as the nominal port so
/// generic URL parsing and node identity keep working.
fn extract_hy2_hop_ports(link: &str) -> Result<(Cow<'_, str>, Option<String>), ConfigError> {
    let Some(scheme_len) = ["hysteria2://", "hysteria://"]
        .iter()
        .find(|prefix| link.starts_with(**prefix))
        .map(|prefix| prefix.len())
    else {
        return Ok((Cow::Borrowed(link), None));
    };
    let rest = &link[scheme_len..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let colon = if host_port.starts_with('[') {
        match host_port.find(']') {
            Some(close) if host_port.as_bytes().get(close + 1) == Some(&b':') => close + 1,
            _ => return Ok((Cow::Borrowed(link), None)),
        }
    } else {
        // A bare IPv6 literal has no place in a valid URL; leave it for the
        // URL parser to reject rather than guessing at its last colon.
        let mut colons = host_port.match_indices(':');
        let Some((first, _)) = colons.next() else {
            return Ok((Cow::Borrowed(link), None));
        };
        if colons.next().is_some() {
            return Ok((Cow::Borrowed(link), None));
        }
        first
    };
    let port_spec = &host_port[colon + 1..];
    if !port_spec.contains([',', '-']) {
        return Ok((Cow::Borrowed(link), None));
    }
    if !valid_hop_port_spec(port_spec) {
        return Err(ConfigError::Parse(format!(
            "invalid hysteria2 hop port list '{port_spec}'"
        )));
    }
    let first_port = port_spec
        .split([',', '-'])
        .next()
        .and_then(|part| part.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .ok_or_else(|| ConfigError::Parse(format!("invalid hysteria2 port '{port_spec}'")))?;
    let spec_start = scheme_len + (authority.len() - host_port.len()) + colon + 1;
    let rebuilt = format!(
        "{}{}{}",
        &link[..spec_start],
        first_port,
        &link[scheme_len + authority_end..]
    );
    Ok((Cow::Owned(rebuilt), Some(port_spec.to_string())))
}

/// Comma-separated ports and inclusive port ranges, all nonzero.
fn valid_hop_port_spec(spec: &str) -> bool {
    !spec.is_empty()
        && spec.split(',').all(|segment| {
            let segment = segment.trim();
            match segment.split_once('-') {
                None => segment.parse::<u16>().is_ok_and(|port| port > 0),
                Some((low, high)) => {
                    match (low.trim().parse::<u16>(), high.trim().parse::<u16>()) {
                        (Ok(low), Ok(high)) => low > 0 && low <= high,
                        _ => false,
                    }
                }
            }
        })
}

/// Base64-decode tolerantly: URL-safe without padding first, then the other
/// common alphabets/padding combinations.
fn base64_decode_flexible(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .ok()
}

/// Percent-decode a string into bytes, then lossily into UTF-8.
fn percent_decode_str(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(decoded) = hex_to_byte(bytes[i + 1], bytes[i + 2])
        {
            out.push(decoded);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_to_byte(h: u8, l: u8) -> Result<u8, ()> {
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let hi = hex_val(h).ok_or(())?;
    let lo = hex_val(l).ok_or(())?;
    Ok(hi << 4 | lo)
}
