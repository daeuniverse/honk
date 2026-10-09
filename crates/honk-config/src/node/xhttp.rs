use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use super::TlsOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    #[default]
    #[serde(alias = "")]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

impl XhttpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PacketUp => "packet-up",
            Self::StreamUp => "stream-up",
            Self::StreamOne => "stream-one",
        }
    }
}

impl std::str::FromStr for XhttpMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "" | "auto" => Ok(Self::Auto),
            "packet-up" => Ok(Self::PacketUp),
            "stream-up" => Ok(Self::StreamUp),
            "stream-one" => Ok(Self::StreamOne),
            _ => Err("invalid XHTTP mode"),
        }
    }
}

/// The mode a node actually speaks: `auto` resolved against the carrier security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpResolvedMode {
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct XhttpRange {
    pub min: u32,
    pub max: u32,
}

impl<'de> Deserialize<'de> for XhttpRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_range(deserializer, None)
    }
}

fn deserialize_range<'de, D: Deserializer<'de>>(
    deserializer: D,
    default: Option<XhttpRange>,
) -> Result<XhttpRange, D::Error> {
    struct Range(Option<XhttpRange>);
    impl<'de> serde::de::Visitor<'de> for Range {
        type Value = XhttpRange;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an XHTTP range")
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
            let value = u32::try_from(value).map_err(|_| E::custom("invalid XHTTP range"))?;
            Ok(XhttpRange {
                min: value,
                max: value,
            })
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
            self.visit_u64(u64::try_from(value).map_err(|_| E::custom("invalid XHTTP range"))?)
        }

        fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
            if text.is_empty()
                && let Some(default) = self.0
            {
                return Ok(default);
            }
            let (min, max) = text.split_once('-').unwrap_or((text, text));
            Ok(XhttpRange {
                min: min.parse().map_err(|_| E::custom("invalid XHTTP range"))?,
                max: max.parse().map_err(|_| E::custom("invalid XHTTP range"))?,
            })
        }

        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Bounds {
                min: u32,
                max: u32,
            }
            let bounds = Bounds::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
            Ok(XhttpRange {
                min: bounds.min,
                max: bounds.max,
            })
        }
    }
    let invalid = || <D::Error as serde::de::Error>::custom("invalid XHTTP range");
    let range = deserializer
        .deserialize_any(Range(default))
        .map_err(|_| invalid())?;
    if range.min > range.max {
        return Err(invalid());
    }
    Ok(range)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XhttpOptions {
    pub path: String,
    pub host: Option<String>,
    pub mode: XhttpMode,
    #[serde(deserialize_with = "xhttp_headers")]
    pub headers: BTreeMap<String, String>,
    #[serde(alias = "x-padding-bytes", deserialize_with = "padding_range")]
    pub x_padding_bytes: XhttpRange,
    #[serde(alias = "no-grpc-header")]
    pub no_grpc_header: bool,
    #[serde(alias = "sc-max-each-post-bytes", deserialize_with = "post_range")]
    pub sc_max_each_post_bytes: XhttpRange,
    #[serde(
        alias = "sc-min-posts-interval-ms",
        deserialize_with = "interval_range"
    )]
    pub sc_min_posts_interval_ms: XhttpRange,
    /// Absent options serialize nothing, keeping existing XHTTP node IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<Box<XhttpDownload>>,
}

/// Xray `downloadSettings`: GET requests use their own endpoint and request
/// shape. Like Xray, nothing is inherited from the upload side; the TLS name
/// falls back to the address, never to the upload SNI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpDownload {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default = "default_padding", deserialize_with = "padding_range")]
    pub x_padding_bytes: XhttpRange,
}

fn default_path() -> String {
    "/".into()
}
fn default_padding() -> XhttpRange {
    XhttpOptions::DEFAULT_PADDING
}

impl XhttpDownload {
    fn normalize(&mut self) {
        self.address = self.address.trim().to_ascii_lowercase();
        self.path = XhttpOptions::normalize_path(&self.path);
        self.host = self.host.take().filter(|host| !host.is_empty());
        self.server_name = self.server_name.take().filter(|name| !name.is_empty());
    }

    /// The dialer joins `address:port` textually, so only names and IPv4 literals can be dialed;
    /// anything else would be admitted here and fail on every flow.
    fn validate_address(&self) -> Result<(), &'static str> {
        if self.address.is_empty()
            || !self.address.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'.' | b'_')
            })
        {
            return Err("XHTTP download address must be a normalized hostname or IPv4 address");
        }
        Ok(())
    }
}

impl Default for XhttpOptions {
    fn default() -> Self {
        Self {
            path: "/".into(),
            host: None,
            mode: XhttpMode::Auto,
            headers: BTreeMap::new(),
            x_padding_bytes: Self::DEFAULT_PADDING,
            no_grpc_header: false,
            sc_max_each_post_bytes: Self::DEFAULT_POST,
            sc_min_posts_interval_ms: Self::DEFAULT_INTERVAL,
            download: None,
        }
    }
}

fn padding_range<'de, D: Deserializer<'de>>(deserializer: D) -> Result<XhttpRange, D::Error> {
    deserialize_range(deserializer, Some(XhttpOptions::DEFAULT_PADDING))
}
fn post_range<'de, D: Deserializer<'de>>(deserializer: D) -> Result<XhttpRange, D::Error> {
    deserialize_range(deserializer, Some(XhttpOptions::DEFAULT_POST))
}
fn interval_range<'de, D: Deserializer<'de>>(deserializer: D) -> Result<XhttpRange, D::Error> {
    deserialize_range(deserializer, Some(XhttpOptions::DEFAULT_INTERVAL))
}

fn merge_header(
    headers: &mut BTreeMap<String, String>,
    name: String,
    value: String,
) -> Result<(), &'static str> {
    match headers.entry(name.to_ascii_lowercase()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(value);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &value => {}
        _ => return Err("XHTTP header aliases conflict"),
    }
    Ok(())
}

fn xhttp_headers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    deserialize_headers(deserializer, false)
}

fn deserialize_headers<'de, D: Deserializer<'de>>(
    deserializer: D,
    reject_duplicates: bool,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Headers(bool);
    impl<'de> serde::de::Visitor<'de> for Headers {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an XHTTP header map")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut headers = BTreeMap::new();
            let mut names = std::collections::HashSet::new();
            while let Some(name) = map.next_key::<String>()? {
                // Extra JSON rejects repeated raw keys even when their values agree.
                if self.0 && !names.insert(name.clone()) {
                    return Err(serde::de::Error::custom("duplicate XHTTP header"));
                }
                let value = map.next_value::<String>()?;
                merge_header(&mut headers, name, value).map_err(serde::de::Error::custom)?;
            }
            Ok(headers)
        }
    }
    deserializer.deserialize_map(Headers(reject_duplicates))
}

pub(super) fn deserialize_xhttp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<XhttpOptions>, D::Error> {
    XhttpOptions::deserialize(deserializer)
        .map(Some)
        .map_err(|_| serde::de::Error::custom("invalid XHTTP options"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrayExtra {
    #[serde(default, deserialize_with = "present_option")]
    host: Option<String>,
    #[serde(default, deserialize_with = "present_option")]
    path: Option<String>,
    #[serde(default, deserialize_with = "present_option")]
    mode: Option<XhttpMode>,
    #[serde(default, deserialize_with = "extra_headers")]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "xPaddingBytes", deserialize_with = "extra_padding")]
    x_padding_bytes: Option<XhttpRange>,
    #[serde(default, rename = "noGRPCHeader", deserialize_with = "present_option")]
    no_grpc_header: Option<bool>,
    #[serde(
        default,
        rename = "scMaxEachPostBytes",
        deserialize_with = "extra_post"
    )]
    sc_max_each_post_bytes: Option<XhttpRange>,
    #[serde(
        default,
        rename = "scMinPostsIntervalMs",
        deserialize_with = "extra_interval"
    )]
    sc_min_posts_interval_ms: Option<XhttpRange>,
    #[serde(
        default,
        rename = "downloadSettings",
        deserialize_with = "present_option"
    )]
    download_settings: Option<XrayDownload>,
    // Xray reads these only in its server hub; a client checks the type and sends nothing.
    #[serde(default, rename = "noSSEHeader", deserialize_with = "present_option")]
    _no_sse_header: Option<bool>,
    #[serde(
        default,
        rename = "scMaxBufferedPosts",
        deserialize_with = "present_option"
    )]
    _sc_max_buffered_posts: Option<u64>,
    #[serde(
        default,
        rename = "scStreamUpServerSecs",
        deserialize_with = "present_option"
    )]
    _sc_stream_up_server_secs: Option<XhttpRange>,
    #[serde(default, rename = "xmux", deserialize_with = "present_option")]
    _xmux: Option<DefaultXmux>,
}

/// XMUX that is all-zero or exactly Xray's fill-in for an omitted XMUX
/// (`infra/conf/transport_internet.go`). Accepting it adds no deviation beyond
/// honk's fixed carrier reuse; any other value rejects.
pub struct DefaultXmux;

impl<'de> Deserialize<'de> for DefaultXmux {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Xray reads omitted members and empty strings as zero.
        #[derive(PartialEq)]
        struct Range(XhttpRange);
        impl Default for Range {
            fn default() -> Self {
                Self(XhttpRange { min: 0, max: 0 })
            }
        }
        impl<'de> Deserialize<'de> for Range {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_range(deserializer, Some(Self::default().0)).map(Self)
            }
        }
        // Xray spells these in camelCase, mihomo `reuse-settings` in kebab-case.
        #[derive(Deserialize, Default, PartialEq)]
        #[serde(default, deny_unknown_fields, rename_all = "camelCase")]
        struct Xmux {
            #[serde(alias = "max-concurrency")]
            max_concurrency: Range,
            #[serde(alias = "max-connections")]
            max_connections: Range,
            #[serde(alias = "c-max-reuse-times")]
            c_max_reuse_times: Range,
            #[serde(alias = "h-max-request-times")]
            h_max_request_times: Range,
            #[serde(alias = "h-max-reusable-secs")]
            h_max_reusable_secs: Range,
            #[serde(alias = "h-keep-alive-period")]
            h_keep_alive_period: i64,
        }
        let range = |min, max| Range(XhttpRange { min, max });
        let filled = Xmux {
            max_concurrency: range(1, 1),
            h_max_request_times: range(600, 900),
            h_max_reusable_secs: range(1800, 3000),
            ..Xmux::default()
        };
        let xmux = Xmux::deserialize(deserializer)?;
        if xmux == Xmux::default() || xmux == filled {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("unsupported XHTTP XMUX option"))
        }
    }
}

/// Xray `downloadSettings` (a StreamConfig) as exporters write it. Only an
/// H2-over-TLS XHTTP endpoint is representable; known null members are absent,
/// as in Go's decoder, and unknown members reject whatever their value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XrayDownload {
    address: String,
    port: u16,
    network: String,
    security: String,
    alpn: Option<Vec<String>>,
    #[serde(rename = "tlsSettings")]
    tls_settings: Option<XrayDownloadTls>,
    #[serde(rename = "xhttpSettings")]
    xhttp_settings: Option<XrayDownloadXhttp>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct XrayDownloadTls {
    #[serde(rename = "serverName")]
    server_name: Option<String>,
    // Global TLS mode owns the fingerprint, as for the upload `fp`.
    #[serde(rename = "fingerprint")]
    _fingerprint: Option<String>,
    alpn: Option<Vec<String>>,
    #[serde(rename = "allowInsecure")]
    allow_insecure: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct XrayDownloadXhttp {
    path: Option<String>,
    host: Option<String>,
    // GET carries no mode; the upload side resolves it.
    #[serde(rename = "mode")]
    _mode: Option<XhttpMode>,
}

impl XrayDownload {
    pub fn into_download(self) -> Result<XhttpDownload, &'static str> {
        let tls = self.tls_settings.unwrap_or_default();
        let xhttp = self.xhttp_settings.unwrap_or_default();
        let h2_only = |alpn: Option<Vec<String>>| {
            let mut alpn = alpn.unwrap_or_default();
            XhttpOptions::normalize_alpn(&mut alpn);
            alpn.is_empty() || alpn == ["h2"]
        };
        if self.address.trim().is_empty()
            || crate::options::vocab::xhttp_stream_transport(&self.network) != Ok("xhttp")
            || !self.security.eq_ignore_ascii_case("tls")
            || !h2_only(self.alpn)
            || !h2_only(tls.alpn)
            || tls.allow_insecure == Some(true)
        {
            return Err("unsupported XHTTP download settings");
        }
        Ok(XhttpDownload {
            address: self.address,
            port: self.port,
            server_name: tls.server_name,
            host: xhttp.host,
            path: xhttp.path.unwrap_or_else(default_path),
            x_padding_bytes: XhttpOptions::DEFAULT_PADDING,
        })
    }
}

pub(crate) fn present_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}
fn extra_headers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, String>>, D::Error> {
    deserialize_headers(deserializer, true).map(Some)
}
fn extra_padding<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<XhttpRange>, D::Error> {
    padding_range(deserializer).map(Some)
}
fn extra_post<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<XhttpRange>, D::Error> {
    post_range(deserializer).map(Some)
}
fn extra_interval<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<XhttpRange>, D::Error> {
    interval_range(deserializer).map(Some)
}

struct Extra;
impl<'de> serde::de::Visitor<'de> for Extra {
    type Value = XrayExtra;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an XHTTP extra object or encoded object")
    }
    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
        XrayExtra::parse(text).map_err(E::custom)
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        XrayExtra::deserialize(serde::de::value::MapAccessDeserializer::new(map))
    }
}

pub(crate) fn deserialize_xray_extra<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<XrayExtra>, D::Error> {
    deserializer.deserialize_any(Extra).map(Some)
}

impl XrayExtra {
    pub(crate) fn parse(text: &str) -> Result<Self, &'static str> {
        let mut decoder = serde_json::Deserializer::from_str(text);
        // URI extra is an object, unlike VMess's object-or-encoded-object field.
        let extra = decoder
            .deserialize_map(Extra)
            .map_err(|_| "invalid XHTTP extra option")?;
        decoder.end().map_err(|_| "invalid XHTTP extra option")?;
        Ok(extra)
    }
}

impl XhttpOptions {
    const DEFAULT_PADDING: XhttpRange = XhttpRange {
        min: 100,
        max: 1000,
    };
    const DEFAULT_POST: XhttpRange = XhttpRange {
        min: 1_000_000,
        max: 1_000_000,
    };
    const DEFAULT_INTERVAL: XhttpRange = XhttpRange { min: 30, max: 30 };
    const MAX_PATH_BYTES: usize = 16 * 1024;

    /// Dot segments and escapes are wire data, not URL resolution instructions.
    pub fn normalize_path(value: &str) -> String {
        let (path, query) = value
            .split_once('?')
            .map_or((value, None), |(path, query)| (path, Some(query)));
        let mut normalized = String::with_capacity(value.len() + 2);
        if !path.starts_with('/') {
            normalized.push('/');
        }
        normalized.push_str(path);
        if !normalized.ends_with('/') {
            normalized.push('/');
        }
        if let Some(query) = query {
            normalized.push('?');
            normalized.push_str(query);
        }
        normalized
    }

    /// Blank members are absent and adjacent repeats carry no information.
    pub(crate) fn normalize_alpn(protocols: &mut Vec<String>) {
        protocols.retain_mut(|protocol| {
            protocol.truncate(protocol.trim_end().len());
            let leading = protocol.len() - protocol.trim_start().len();
            protocol.drain(..leading);
            !protocol.is_empty()
        });
        protocols.dedup();
    }

    pub fn normalize(&mut self) -> Result<(), &'static str> {
        self.path = Self::normalize_path(&self.path);
        self.host = self.host.take().filter(|host| !host.is_empty());
        let mut headers = BTreeMap::new();
        for (name, value) in std::mem::take(&mut self.headers) {
            merge_header(&mut headers, name, value)?;
        }
        self.headers = headers;
        if let Some(download) = &mut self.download {
            download.normalize();
        }
        self.validate()
    }

    /// Validate canonical options for immutable node admission.
    pub fn validate(&self) -> Result<(), &'static str> {
        for (range, min, max) in [
            (self.x_padding_bytes, 1, 8192),
            (self.sc_max_each_post_bytes, 1, 16 * 1024 * 1024),
            (self.sc_min_posts_interval_ms, 0, 60_000),
        ] {
            if range.min < min || range.min > range.max || range.max > max {
                return Err("XHTTP range exceeds supported bounds");
            }
        }
        let path = self
            .path
            .split_once('?')
            .map_or(self.path.as_str(), |(path, _)| path);
        if !path.starts_with('/') || !path.ends_with('/') {
            return Err("XHTTP path must be normalized before admission");
        }
        // Escaping can triple a path byte; the request target must stay inside the HTTP parser's limit.
        if self.path.len() > Self::MAX_PATH_BYTES
            || self.path.contains('#')
            || self.path.bytes().any(|byte| byte < b' ' || byte == 127)
            // The normalized trailing slash lets the URI parser check only the unescaped query.
            || self.path[path.len() - 1..].parse::<http::uri::PathAndQuery>().is_err()
        {
            return Err("invalid XHTTP path");
        }
        if let Some(host) = &self.host
            && (host.is_empty()
                || host.parse::<http::uri::Authority>().is_err()
                || host.contains('@')
                || host.bytes().any(|byte| byte <= b' ' || byte == 127))
        {
            return Err("invalid XHTTP host");
        }
        let mut bytes = 0usize;
        if self.headers.len() > 64 {
            return Err("too many XHTTP headers");
        }
        for (name, value) in &self.headers {
            if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
                return Err("XHTTP headers must be normalized before admission");
            }
            if name.parse::<http::header::HeaderName>().is_err()
                || matches!(
                    name.as_str(),
                    "host"
                        | "content-type"
                        | "content-length"
                        | "referer"
                        | "connection"
                        | "transfer-encoding"
                        | "keep-alive"
                        | "proxy-connection"
                        | "upgrade"
                        | "te"
                        | "trailer"
                )
                || http::header::HeaderValue::from_str(value).is_err()
                || value.bytes().any(|byte| byte < 32 || byte == 127)
            {
                return Err("invalid or protocol-managed XHTTP header");
            }
            bytes += name.len() + value.len();
        }
        if bytes > 16 * 1024 {
            return Err("XHTTP headers exceed supported bounds");
        }
        if let Some(download) = &self.download {
            // Xray and mihomo refuse this combination; the download view validates the rest.
            if self.mode == XhttpMode::StreamOne {
                return Err("XHTTP download settings cannot use stream-one mode");
            }
            download.validate_address()?;
        }
        Ok(())
    }

    /// `auto` becomes stream-one over REALITY and packet-up otherwise.
    pub fn resolved_mode(&self, tls: &TlsOptions) -> Result<XhttpResolvedMode, &'static str> {
        let reality = (self.mode == XhttpMode::Auto || !tls.enabled)
            && tls.effective_reality_public_key()?.is_some();
        Ok(match self.mode {
            XhttpMode::Auto if reality => XhttpResolvedMode::StreamOne,
            XhttpMode::Auto | XhttpMode::PacketUp => XhttpResolvedMode::PacketUp,
            XhttpMode::StreamUp => XhttpResolvedMode::StreamUp,
            XhttpMode::StreamOne => XhttpResolvedMode::StreamOne,
        })
    }

    pub(crate) fn from_xray_extra(
        extra: Option<XrayExtra>,
        path: Option<&str>,
        host: Option<&str>,
        mode: Option<XhttpMode>,
    ) -> Result<Self, &'static str> {
        let mut options = Self::default();
        if let Some(extra) = extra {
            options.path = extra.path.unwrap_or(options.path);
            options.host = extra.host;
            options.mode = extra.mode.unwrap_or_default();
            options.headers = extra.headers.unwrap_or_default();
            options.x_padding_bytes = extra.x_padding_bytes.unwrap_or(Self::DEFAULT_PADDING);
            options.no_grpc_header = extra.no_grpc_header.unwrap_or_default();
            options.sc_max_each_post_bytes =
                extra.sc_max_each_post_bytes.unwrap_or(Self::DEFAULT_POST);
            options.sc_min_posts_interval_ms = extra
                .sc_min_posts_interval_ms
                .unwrap_or(Self::DEFAULT_INTERVAL);
            options.download = extra
                .download_settings
                .map(XrayDownload::into_download)
                .transpose()?
                .map(Box::new);
        }
        if let Some(path) = path {
            options.path = path.to_owned();
        }
        if let Some(host) = host {
            options.host = Some(host.to_owned());
        }
        if let Some(mode) = mode {
            options.mode = mode;
        }
        options.normalize()?;
        Ok(options)
    }
}
