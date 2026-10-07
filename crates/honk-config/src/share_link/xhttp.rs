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
        if !(key == "headerType" && matches!(value.as_str(), "" | "none")) && !matches!(
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
        ) {
            return Err(invalid("unsupported XHTTP URI option"));
        }
    }
    let path = coalesce_equal(
        query
            .values("path")
            .map(|path| Ok(Some(XhttpOptions::normalize_path(path)))),
        "XHTTP path claims conflict",
    )
    .map_err(invalid)?
    .unwrap_or_else(|| "/".into());
    let host = coalesce_equal(
        query.values("host").map(|host| Ok(Some(host.to_string()))),
        "XHTTP host claims conflict",
    )
    .map_err(invalid)?
    .filter(|host| !host.is_empty());
    let mode = coalesce_equal(
        query.values("mode").map(|mode| mode.parse().map(Some)),
        "XHTTP mode claims conflict",
    )
    .map_err(invalid)?
    .unwrap_or_default();
    let options = XhttpOptions {
        path,
        host,
        mode,
        ..Default::default()
    };
    let extra = coalesce_equal(
        query.values("extra").map(|extra| {
            let mut claim = options.clone();
            claim.apply_xray_extra(XrayExtra::parse(extra)?)?;
            Ok(Some(claim))
        }),
        "XHTTP extra claims conflict",
    )
    .map_err(invalid)?;
    transport.xhttp = Some(extra.unwrap_or(options));
    transport.transport = "xhttp".into();
    let alpn = coalesce_equal(
        query.values("alpn").map(|value| {
            let mut protocols = value.split(',').map(str::trim).filter(|value| !value.is_empty()).map(str::to_string).collect::<Vec<_>>();
            protocols.dedup();
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
    if json.additional.keys().any(|key| !matches!(key.as_str(), "v" | "fp" | "insecure" | "allowInsecure"))
    {
        return Err(invalid());
    }
    let mode = coalesce_equal(
        mode.map(Some).into_iter().map(Ok).chain(json.r#type.as_deref().filter(|value| !matches!(*value, "" | "none")).map(|value| value.parse().map(Some))),
        "XHTTP mode claims conflict",
    ).map_err(|_| invalid())?;
    if let Some(insecure) = coalesce_equal(
        ["insecure", "allowInsecure"].into_iter().filter_map(|key| json.additional.get(key)).map(|value| {
            match value {
                serde_json::Value::Bool(value) => Ok(Some(*value)),
                serde_json::Value::Number(value) if value.as_u64() == Some(0) => Ok(Some(false)),
                serde_json::Value::Number(value) if value.as_u64() == Some(1) => Ok(Some(true)),
                serde_json::Value::String(value) => crate::options::vocab::verification_text(value).map(Some),
                _ => Err("invalid certificate verification boolean"),
            }
        }), "conflicting certificate verification aliases",
    ).map_err(|_| invalid())? {
        tls.skip_cert_verify = insecure;
    }
    let mut options = XhttpOptions {
        path: json.path.clone().unwrap_or_else(|| "/".into()),
        host: json.host.clone(),
        mode: mode.unwrap_or_default(),
        ..Default::default()
    };
    if let Some(extra) = extra {
        options.apply_xray_extra(extra).map_err(|_| invalid())?;
    }
    options.normalize().map_err(|_| invalid())?;
    stream.transport = "xhttp".into();
    stream.xhttp = Some(options);
    if let Some(alpn) = &json.alpn {
        tls.alpn = alpn.split(',').map(str::to_string).collect();
    }
    Ok(())
}
