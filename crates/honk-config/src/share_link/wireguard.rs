use crate::diagnostic::SourceRef;
use crate::error::DetailedConfigError;
use crate::node::{
    Node, OutboundConfig, WireGuardConfig, WireGuardKey, parse_wireguard_addresses,
    parse_wireguard_allowed_ips, parse_wireguard_reserved,
};
use crate::options::vocab::{coalesce_equal, packet_network};
use crate::types::NodeProtocol;

use super::options::{Query, query_error};

fn claim<T: PartialEq>(
    query: &Query,
    keys: &[&str],
    field: &'static str,
    source: &SourceRef,
    parse: impl Fn(&str) -> Result<T, &'static str>,
) -> Result<Option<T>, DetailedConfigError> {
    coalesce_equal(
        query
            .0
            .iter()
            .filter(|(key, _)| keys.iter().any(|alias| key.eq_ignore_ascii_case(alias)))
            .map(|(_, value)| parse(value).map(Some)),
        "WireGuard parameter aliases must agree",
    )
    .map_err(|message| query_error(source, &[field], "invalid-config-value", message))
}

pub(super) fn parse(
    url: &url::Url,
    source: &SourceRef,
    emit: &mut impl FnMut(crate::diagnostic::DetailedDiagnostic),
) -> Result<Node, DetailedConfigError> {
    let invalid = |field, message| query_error(source, &[field], "invalid-config-value", message);
    let query = super::options::parse_query(url, NodeProtocol::WireGuard, false, source)?;
    if query
        .0
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("peers"))
    {
        return Err(query_error(
            source,
            &["peers"],
            "unsupported-wireguard-peers",
            "WireGuard share links describe exactly one peer",
        ));
    }
    if query.0.iter().any(|(key, _)| {
        [
            "jc",
            "jmin",
            "jmax",
            "s1",
            "s2",
            "s3",
            "s4",
            "h1",
            "h2",
            "h3",
            "h4",
            "i1",
            "i2",
            "i3",
            "i4",
            "i5",
            "headerprotectionkey",
        ]
        .iter()
        .any(|marker| key.eq_ignore_ascii_case(marker))
    }) {
        return Err(invalid(
            "protocol",
            "AmneziaWG wire extensions are unsupported",
        ));
    }
    let parse_key = |value: &str| value.replace(' ', "+").parse::<WireGuardKey>();
    let private_query = claim(
        &query,
        &["privatekey", "private_key", "private-key", "pk"],
        "wg_private_key",
        source,
        parse_key,
    )?;
    if url.password().is_some() {
        return Err(invalid(
            "wg_private_key",
            "WireGuard userinfo must contain only the private key",
        ));
    }
    let private_user = super::percent_decode_credential(
        (!url.username().is_empty()).then(|| url.username()),
        source,
    )?
    .map(|value| value.parse::<WireGuardKey>())
    .transpose()
    .map_err(|message| invalid("wg_private_key", message))?;
    let private_key = coalesce_equal(
        [Ok(private_user), Ok(private_query)],
        "WireGuard private key aliases must agree",
    )
    .map_err(|message| invalid("wg_private_key", message))?;
    let public_key = claim(
        &query,
        &[
            "publickey",
            "public_key",
            "public-key",
            "peer_pk",
            "peer_public_key",
        ],
        "wg_public_key",
        source,
        parse_key,
    )?;
    let preshared_key = claim(
        &query,
        &[
            "presharedkey",
            "preshared_key",
            "pre_shared_key",
            "pre-shared-key",
            "psk",
        ],
        "wg_preshared_key",
        source,
        parse_key,
    )?;
    let (mut local_v4, mut local_v6) = claim(
        &query,
        &["address", "local_address", "local-address"],
        "wg_addresses",
        source,
        |value| parse_wireguard_addresses([value]),
    )?
    .unwrap_or_default();
    if let Some((v4, v6)) = claim(&query, &["selfip"], "wg_addresses", source, |value| {
        parse_wireguard_addresses([value])
    })? {
        if v6.is_some() || local_v4.is_some_and(|address| Some(address) != v4) {
            return Err(invalid(
                "wg_addresses",
                "WireGuard local IPv4 address claims must agree",
            ));
        }
        local_v4 = v4;
    }
    if let Some((v4, v6)) = claim(&query, &["selfipv6"], "wg_addresses", source, |value| {
        parse_wireguard_addresses([value])
    })? {
        if v4.is_some() || local_v6.is_some_and(|address| Some(address) != v6) {
            return Err(invalid(
                "wg_addresses",
                "WireGuard local IPv6 address claims must agree",
            ));
        }
        local_v6 = v6;
    }
    let mut config = WireGuardConfig {
        private_key,
        public_key,
        preshared_key,
        local_v4,
        local_v6,
        mtu: claim(&query, &["mtu"], "wg_mtu", source, |value| {
            value
                .trim()
                .parse::<u16>()
                .map_err(|_| "WireGuard MTU must be an unsigned 16-bit integer")
        })?
        .unwrap_or(1420),
        persistent_keepalive: claim(
            &query,
            &[
                "keepalive",
                "keep-alive",
                "persistent-keepalive",
                "persistent_keepalive",
                "persistent_keepalive_interval",
            ],
            "wg_keepalive",
            source,
            |value| {
                value
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| "WireGuard keepalive must be an unsigned 16-bit number of seconds")
            },
        )?,
        reserved: claim(
            &query,
            &["reserved", "client_id", "client-id"],
            "wg_reserved",
            source,
            |value| parse_wireguard_reserved(&value.replace(' ', "+")),
        )?,
        ..WireGuardConfig::default()
    };
    if let Some(allowed_ips) = claim(
        &query,
        &["allowedips", "allowed_ips", "allowed-ips"],
        "wg_allowed_ips",
        source,
        parse_wireguard_allowed_ips,
    )? {
        config.allowed_ips = allowed_ips;
    }
    let udp = claim(&query, &["udp"], "network", source, |value| {
        if value == "1" || value.eq_ignore_ascii_case("true") {
            Ok(true)
        } else if value == "0" || value.eq_ignore_ascii_case("false") {
            Ok(false)
        } else {
            Err("WireGuard udp must be 1/true or 0/false")
        }
    })?;
    let network = claim(&query, &["network"], "network", source, |value| {
        packet_network(value).map(|udp| udp.unwrap_or(true))
    })?;
    let udp = coalesce_equal(
        [Ok(udp), Ok(network)],
        "WireGuard UDP permission claims must agree",
    )
    .map_err(|message| invalid("network", message))?;
    config.network = (udp == Some(false)).then(|| "tcp".into());
    config.normalize();
    config
        .check()
        .map_err(|(field, message)| invalid(field, message))?;
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| invalid("host", "WireGuard requires an endpoint host"))?
        .to_owned();
    let port = url.port().filter(|port| *port != 0).ok_or_else(|| {
        invalid(
            "port",
            "WireGuard requires an explicit nonzero endpoint port",
        )
    })?;
    let name = url
        .fragment()
        .map(super::percent_decode_str)
        .filter(|name| !name.is_empty())
        .or_else(|| query.get("remark").filter(|name| !name.is_empty()).cloned())
        .unwrap_or_else(|| format!("{}-{host}", url.scheme()));
    let mut node = Node {
        name,
        address: format!("{host}:{port}"),
        host,
        port,
        outbound: OutboundConfig::WireGuard(config),
        ..Node::default()
    };
    super::options::apply_tls(&mut node, &query, false, source, emit)?;
    super::options::apply_protocol(&mut node, &query, None, false, source, emit)?;
    Ok(node)
}
