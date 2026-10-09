use crate::diagnostic::SourceRef;
use crate::error::{ConfigError, DetailedConfigError};
use crate::node::{Node, StreamTransportOptions, TlsOptions, XhttpOptions, XrayExtra};
use crate::options::vocab::{coalesce_equal, xhttp_stream_transport};

use super::options::{Query, query_error};

pub(super) fn is_xhttp_link(url: &url::Url) -> bool {
    url.query_pairs().any(|(key, value)| {
        matches!(key.as_ref(), "type" | "network") && xhttp_stream_transport(&value) == Ok("xhttp")
    })
}

pub(super) fn is_xhttp_parameter(key: &str) -> bool {
    matches!(key, "host" | "path" | "mode" | "extra" | "alpn")
}

pub(super) fn apply_xhttp_query(
    node: &mut Node,
    query: &Query,
    source: &SourceRef,
) -> Result<bool, DetailedConfigError> {
    let invalid = |message| query_error(source, &["xhttp"], "invalid-config-value", message);
    let Some(transport) = node.transport_mut() else {
        return if query.1 {
            Err(invalid("XHTTP options require a stream protocol"))
        } else {
            Ok(false)
        };
    };
    if xhttp_stream_transport(&transport.transport) != Ok("xhttp") {
        return Ok(false);
    }
    for (key, value) in &query.0 {
        // Exporter metadata with no XHTTP request effect. Xray's padding overwrites
        // any Referer header, so a Referer-only header claim never reaches the wire.
        let inert = match key.as_str() {
            "headerType" | "quicSecurity" => matches!(value.as_str(), "" | "none"),
            "serviceName" => value.is_empty(),
            "headers" => serde_json::from_str::<std::collections::BTreeMap<String, String>>(value)
                .is_ok_and(|headers| {
                    headers
                        .keys()
                        .all(|name| name.eq_ignore_ascii_case("referer"))
                }),
            _ => false,
        };
        if !inert
            && !matches!(
                key.as_str(),
                "type"
                    | "network"
                    | "host"
                    | "path"
                    | "mode"
                    | "extra"
                    | "alpn"
                    | "security"
                    | "tls"
                    | "sni"
                    | "peer"
                    | "fp"
                    | "allowInsecure"
                    | "allow_insecure"
                    | "insecure"
                    | "pbk"
                    | "sid"
                    | "spx"
                    | "pinSHA256"
                    | "pin_sha256"
                    | "ech"
                    | "ech_config"
                    | "echconfig"
                    | "flow"
                    | "encryption"
                    | "scy"
                    | "udp"
                    | "packetEncoding"
                    | "mux"
                    | "padding"
                    | "concurrency"
                    | "xudpConcurrency"
                    | "xudpProxyUDP443"
                    | "xtls"
                    | "remark"
            )
        {
            return Err(invalid("unsupported XHTTP URI option"));
        }
    }
    let path = coalesce_equal(
        query
            .values("path")
            .map(|path| Ok(Some(XhttpOptions::normalize_path(path)))),
        "XHTTP path claims conflict",
    )
    .map_err(invalid)?;
    let host = coalesce_equal(
        query.values("host").map(|host| Ok(Some(host))),
        "XHTTP host claims conflict",
    )
    .map_err(invalid)?;
    let mode = coalesce_equal(
        query.values("mode").map(|mode| mode.parse().map(Some)),
        "XHTTP mode claims conflict",
    )
    .map_err(invalid)?;
    let extra = coalesce_equal(
        query.values("extra").map(|extra| {
            XhttpOptions::from_xray_extra(
                Some(XrayExtra::parse(extra)?),
                path.as_deref(),
                host,
                mode,
            )
            .map(Some)
        }),
        "XHTTP extra claims conflict",
    )
    .map_err(invalid)?;
    transport.xhttp = Some(match extra {
        Some(options) => options,
        None => {
            XhttpOptions::from_xray_extra(None, path.as_deref(), host, mode).map_err(invalid)?
        }
    });
    transport.transport = "xhttp".into();
    let alpn = coalesce_equal(
        query.values("alpn").map(|value| {
            let mut protocols = value.split(',').map(str::to_string).collect::<Vec<_>>();
            XhttpOptions::normalize_alpn(&mut protocols);
            Ok((!protocols.is_empty()).then_some(protocols))
        }),
        "XHTTP ALPN claims conflict",
    )
    .map_err(|message| query_error(source, &["tls_alpn"], "invalid-config-value", message))?;
    if let Some(alpn) = alpn {
        node.tls_mut().expect("stream TLS options").alpn = alpn;
    }
    Ok(true)
}

pub(super) fn apply_vmess_xhttp(
    json: &super::VmessLinkJson,
    mode: Option<crate::node::XhttpMode>,
    extra: Option<XrayExtra>,
    stream: &mut StreamTransportOptions,
    tls: &mut TlsOptions,
) -> Result<(), ConfigError> {
    let invalid = || ConfigError::Parse("unsupported or invalid VMess XHTTP option".into());
    if json
        .additional
        .keys()
        .any(|key| !matches!(key.as_str(), "v" | "fp" | "insecure" | "allowInsecure"))
    {
        return Err(invalid());
    }
    let mode = coalesce_equal(
        mode.map(Some).into_iter().map(Ok).chain(
            json.r#type
                .as_deref()
                .filter(|value| !matches!(*value, "" | "none"))
                .map(|value| value.parse().map(Some)),
        ),
        "XHTTP mode claims conflict",
    )
    .map_err(|_| invalid())?;
    let options =
        XhttpOptions::from_xray_extra(extra, json.path.as_deref(), json.host.as_deref(), mode)
            .map_err(|_| invalid())?;
    stream.transport = "xhttp".into();
    stream.xhttp = Some(options);
    if let Some(alpn) = &json.alpn {
        tls.alpn = alpn.split(',').map(str::to_string).collect();
    }
    Ok(())
}
