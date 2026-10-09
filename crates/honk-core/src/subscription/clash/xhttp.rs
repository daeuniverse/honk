//! Mihomo `xhttp-opts`, including the Xray-shaped `download-settings` panels emit.

use honk_config::node::{DefaultXmux, XhttpDownload, XhttpOptions, XhttpRange, XrayDownload};
use serde_yaml::{Mapping, Value};

pub(super) fn options(value: &Value) -> Result<XhttpOptions, &'static str> {
    let mut options = value
        .as_mapping()
        .ok_or("xhttp-opts must be a mapping")?
        .clone();
    // `download` is the canonical field, not a mihomo key.
    if options.contains_key("download") {
        return Err("invalid XHTTP options");
    }
    drop_server_claims(&mut options)?;
    let download = options
        .remove("download-settings")
        .map(download_settings)
        .transpose()?;
    let mut xhttp: XhttpOptions =
        serde_yaml::from_value(Value::Mapping(options)).map_err(|_| "invalid XHTTP options")?;
    xhttp.download = download.map(Box::new);
    Ok(xhttp)
}

fn drop_checked<T: serde::de::DeserializeOwned>(
    options: &mut Mapping,
    key: &str,
) -> Result<(), &'static str> {
    match options.remove(key) {
        Some(value) => serde_yaml::from_value::<T>(value)
            .map(drop)
            .map_err(|_| "invalid XHTTP options"),
        None => Ok(()),
    }
}

/// Server-only options and default XMUX leave a client's requests unchanged.
fn drop_server_claims(options: &mut Mapping) -> Result<(), &'static str> {
    drop_checked::<bool>(options, "no-sse-header")?;
    drop_checked::<i64>(options, "sc-max-buffered-posts")?;
    drop_checked::<XhttpRange>(options, "sc-stream-up-server-secs")?;
    drop_checked::<DefaultXmux>(options, "xmux")?;
    drop_checked::<DefaultXmux>(options, "reuse-settings")
}

/// Panels emit an Xray StreamConfig plus flat mihomo-style keys here. Mihomo
/// itself ignores the Xray keys and would send GETs to the upload server;
/// honk follows the Xray meaning the same subscription's URIs carry. Keys of
/// mihomo's own inheriting format (`server`, `servername`, `tls`, ...) reject.
fn download_settings(value: Value) -> Result<XhttpDownload, &'static str> {
    let invalid = "invalid XHTTP download-settings";
    let Value::Mapping(mut flat) = value else {
        return Err(invalid);
    };
    let mut xray = Mapping::new();
    for key in [
        "address",
        "port",
        "network",
        "security",
        "alpn",
        "tlsSettings",
        "xhttpSettings",
    ] {
        if let Some(value) = flat.remove(key) {
            xray.insert(key.into(), value);
        }
    }
    let padding = flat
        .remove("x-padding-bytes")
        .map(serde_yaml::from_value::<XhttpRange>)
        .transpose()
        .map_err(|_| invalid)?;
    // Upload-only request options: a GET sends none of them.
    drop_checked::<bool>(&mut flat, "no-grpc-header")?;
    drop_checked::<XhttpRange>(&mut flat, "sc-max-each-post-bytes")?;
    drop_checked::<XhttpRange>(&mut flat, "sc-min-posts-interval-ms")?;
    drop_server_claims(&mut flat)?;
    if !flat.is_empty() {
        return Err(invalid);
    }
    let mut download = serde_yaml::from_value::<XrayDownload>(Value::Mapping(xray))
        .map_err(|_| invalid)?
        .into_download()?;
    if let Some(padding) = padding {
        download.x_padding_bytes = padding;
    }
    Ok(download)
}
