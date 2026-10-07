use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

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

    pub fn normalize(&mut self) -> Result<(), &'static str> {
        self.path = Self::normalize_path(&self.path);
        self.host = self.host.take().filter(|host| !host.is_empty());
        let mut headers = BTreeMap::new();
        for (name, value) in std::mem::take(&mut self.headers) {
            merge_header(&mut headers, name, value)?;
        }
        self.headers = headers;
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
        if self.path.contains('#')
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
        Ok(())
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
            options.sc_max_each_post_bytes = extra.sc_max_each_post_bytes.unwrap_or(Self::DEFAULT_POST);
            options.sc_min_posts_interval_ms = extra.sc_min_posts_interval_ms.unwrap_or(Self::DEFAULT_INTERVAL);
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
