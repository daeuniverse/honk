//! Share-link parsing: build a [`Node`] from a proxy share URI.
//!
//! Supports the common `scheme://` share-link formats (socks5, ss,
//! trojan, anytls, vmess, vless, hysteria2/hy2, tuic, juicity).
//! Shadowsocks links follow SIP002: the userinfo is either
//! `base64(method:password)` or plain `method:password` (the method itself
//! may still be base64-encoded), the whole `method:password@host:port`
//! authority may also be base64-encoded, and an optional `/?plugin=...`
//! query suffix carries the plugin name and options.
//!
//! `vmess://<base64>` v2rayN links carry a JSON object with the fields
//! (`add`, `port`, `id`, `scy`, `net`, `host`, `path`, `tls`, `sni`, ...).
//! Shadowrocket links instead encode `auto:UUID@host:port` as the authority
//! and carry transport/TLS options in the query.
//!
//! This is the single share-link parser for the whole workspace: the dae
//! config parser and the core subscription fetcher both delegate to
//! [`Node::from_share_link`].

use std::borrow::Cow;

use base64::Engine as _;

use crate::error::ConfigError;
use crate::node::{Node, OutboundConfig};

mod options;

impl Node {
    /// Parse a proxy share link (e.g. `ss://...`, `trojan://...`) into a [`Node`].
    /// A chain describes several hops; only the first is parsed.
    pub fn from_share_link(link: &str) -> Result<Node, ConfigError> {
        let first = link.split("->").next().unwrap_or("").trim();
        let (decoded, shadowrocket) = match first.split_once("://") {
            Some((scheme, payload)) if scheme.eq_ignore_ascii_case("vmess") => {
                let Some(decoded) = decode_full_base64_vmess_link(payload)? else {
                    return parse_vmess_link(payload);
                };
                (Some(decoded), true)
            }
            Some((scheme, payload)) if scheme.eq_ignore_ascii_case("vless") => {
                let decoded = decode_full_base64_vless_link(payload)?;
                let shadowrocket = decoded.is_some();
                (decoded, shadowrocket)
            }
            Some((scheme, payload)) if scheme.eq_ignore_ascii_case("ss") => {
                (decode_full_base64_ss_link(payload), false)
            }
            _ => (None, false),
        };
        let first = decoded.as_deref().unwrap_or(first);
        let (first, embedded_hop_ports) = extract_hy2_hop_ports(first)?;
        let url = url::Url::parse(first.as_ref())
            .map_err(|_| ConfigError::Parse("invalid share link syntax".into()))?;
        let mut node = node_from_url(&url)?;
        let query = options::parse_query(&url, node.protocol(), shadowrocket)?;
        node.name = url
            .fragment()
            .map(percent_decode_str)
            .filter(|name| !name.is_empty())
            .or_else(|| query.get("remark").filter(|name| !name.is_empty()).cloned())
            .unwrap_or_else(|| format!("{}-{}", url.scheme(), node.host));

        options::apply_tls(&mut node, &query, shadowrocket)?;
        options::apply_transport(&mut node, &query, shadowrocket)?;
        options::apply_protocol(&mut node, &query, embedded_hop_ports, shadowrocket)?;
        node.validate_protocol()?;
        node.id = node.derive_id();
        Ok(node)
    }
}

fn node_from_url(url: &url::Url) -> Result<Node, ConfigError> {
    let outbound = match url.scheme() {
        "socks5" | "socks4" | "socks4a" => OutboundConfig::Socks5(Default::default()),
        "ss" => OutboundConfig::Shadowsocks(Default::default()),
        "trojan" => OutboundConfig::Trojan(Default::default()),
        "anytls" => OutboundConfig::AnyTls(Default::default()),
        "vmess" => OutboundConfig::Vmess(Default::default()),
        "vless" => OutboundConfig::Vless(Default::default()),
        "hysteria2" | "hysteria" | "hy2" => OutboundConfig::Hysteria2(Default::default()),
        "tuic" => OutboundConfig::Tuic(Default::default()),
        "juicity" => OutboundConfig::Juicity(Default::default()),
        scheme => return Err(ConfigError::UnknownProtocol(scheme.to_string())),
    };
    let host = url
        .host_str()
        .ok_or_else(|| ConfigError::Parse("missing host in share link".into()))?
        .to_string();
    let port = match url.port() {
        Some(0) => return Err(ConfigError::Parse("invalid share link port".into())),
        Some(port) => port,
        None => 443,
    };
    let mut node = Node {
        address: format!("{host}:{port}"),
        host,
        port,
        outbound,
        ..Default::default()
    };
    if let Some(config) = node.shadowsocks_mut() {
        apply_ss_userinfo(config, url);
    } else {
        let username = (!url.username().is_empty()).then(|| percent_decode_str(url.username()));
        let password = url.password().map(percent_decode_str);
        match &mut node.outbound {
            OutboundConfig::Socks5(config) => {
                config.username = username;
                config.password = password;
            }
            OutboundConfig::Trojan(config) => config.password = password.or(username),
            OutboundConfig::Vless(config) => config.uuid = password.or(username),
            OutboundConfig::Hysteria2(config) => {
                config.auth = match (username, password) {
                    (Some(username), Some(password)) => Some(format!("{username}:{password}")),
                    (username, None) => username,
                    (None, Some(password)) => Some(format!(":{password}")),
                };
            }
            OutboundConfig::Tuic(config) => {
                config.uuid = username;
                config.password = password;
            }
            OutboundConfig::Juicity(config) => {
                config.uuid = username;
                config.password = password;
            }
            OutboundConfig::AnyTls(config) => config.password = password.or(username),
            OutboundConfig::Vmess(config) => {
                config.uuid = password.or(username);
                config.encryption = Some("auto".into());
            }
            OutboundConfig::Shadowsocks(_) | OutboundConfig::Direct | OutboundConfig::Block => {}
        }
    }
    Ok(node)
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

fn decode_full_base64_vless_link(rest: &str) -> Result<Option<String>, ConfigError> {
    decode_full_base64_authority(rest, "VLESS", false)
}

fn decode_full_base64_vmess_link(rest: &str) -> Result<Option<String>, ConfigError> {
    decode_full_base64_authority(rest, "VMess", true)
}

fn decode_full_base64_authority(
    rest: &str,
    protocol: &str,
    allow_json: bool,
) -> Result<Option<String>, ConfigError> {
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return Ok(None);
    }
    let invalid = || ConfigError::Parse(format!("invalid {protocol} encoded authority"));
    let decoded = base64_decode_flexible(authority)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(invalid)?;
    if allow_json && decoded.trim_start().starts_with('{') {
        return Ok(None);
    }
    let decoded = decoded.strip_prefix("auto:").unwrap_or(&decoded);
    let (credential, endpoint) = decoded.split_once('@').ok_or_else(invalid)?;
    uuid::Uuid::parse_str(credential).map_err(|_| invalid())?;
    if endpoint.contains(['/', '?', '#', '@', '\\'])
        || endpoint.chars().any(char::is_whitespace)
        || !endpoint.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0)
        })
    {
        return Err(invalid());
    }
    Ok(Some(format!("{protocol}://{decoded}{}", &rest[end..])))
}

/// Split official-style hop ports out of a hysteria2 authority
/// (`hysteria2://auth@host:443,5000-6000/...`). The whole list is the hop
/// set; the first entry stays in the rebuilt address as the nominal port so
/// generic URL parsing and node identity keep working.
fn extract_hy2_hop_ports(link: &str) -> Result<(Cow<'_, str>, Option<String>), ConfigError> {
    let Some((scheme, _)) = link.split_once("://") else {
        return Ok((Cow::Borrowed(link), None));
    };
    if !(scheme.eq_ignore_ascii_case("hysteria2")
        || scheme.eq_ignore_ascii_case("hysteria")
        || scheme.eq_ignore_ascii_case("hy2"))
    {
        return Ok((Cow::Borrowed(link), None));
    }
    let scheme_len = scheme.len() + 3;
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
        return Err(ConfigError::Parse("invalid hysteria2 hop port list".into()));
    }
    let first_port = port_spec
        .split([',', '-'])
        .next()
        .and_then(|part| part.trim().parse::<u16>().ok())
        .ok_or_else(|| ConfigError::Parse("invalid hysteria2 port".into()))?;
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
