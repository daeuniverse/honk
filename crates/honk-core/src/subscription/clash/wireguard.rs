use honk_config::node::{
    Node, OutboundConfig, WireGuardConfig, WireGuardKey, parse_wireguard_addresses,
    parse_wireguard_allowed_ips, parse_wireguard_reserved,
};
use honk_config::options::vocab::{coalesce_equal, packet_network};
use serde_yaml::{Mapping, Value};

use super::super::yaml_value;
use super::fields;

const ONE_PEER: &str =
    "WireGuard supports exactly one peer; multi-peer configurations are unsupported";

fn claim<T: PartialEq>(
    mapping: &Mapping,
    peer: Option<&Mapping>,
    keys: &[&str],
    parse: impl Fn(&Value) -> Result<Option<T>, &'static str>,
) -> Result<Option<T>, &'static str> {
    coalesce_equal(
        std::iter::once(mapping)
            .chain(peer)
            .flat_map(|mapping| keys.iter().filter_map(move |key| yaml_value(mapping, key)))
            .map(parse),
        "WireGuard aliases and peer settings must agree",
    )
}

fn key(value: &Value) -> Result<Option<WireGuardKey>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => value.parse().map(Some),
        _ => Err("WireGuard keys must be base64 strings"),
    }
}

fn list(value: &Value) -> Result<Option<String>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        Value::Sequence(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or("WireGuard IP lists must contain strings")
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|values| Some(values.join(","))),
        _ => Err("WireGuard IP lists must be a string or string array"),
    }
}

fn reserved(value: &Value) -> Result<Option<[u8; 3]>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => parse_wireguard_reserved(value).map(Some),
        Value::Sequence(values) => values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or("WireGuard reserved list must contain three unsigned bytes")
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map(Some)
            .map_err(|_| "WireGuard reserved list must contain three unsigned bytes"),
        _ => Err("WireGuard reserved must be a three-byte list or base64 string"),
    }
}

pub(super) fn parse(
    mapping: &Mapping,
    subscription_id: Option<uuid::Uuid>,
) -> Result<Node, &'static str> {
    let peer = match yaml_value(mapping, "peers") {
        None | Some(Value::Null) => None,
        Some(Value::Sequence(peers)) if peers.len() == 1 => Some(
            peers[0]
                .as_mapping()
                .ok_or("WireGuard peer must be an object")?,
        ),
        Some(Value::Sequence(_)) => return Err(ONE_PEER),
        Some(_) => return Err("WireGuard peers must be an array"),
    };
    for source in std::iter::once(mapping).chain(peer) {
        super::reject_active_unless(
            source,
            &[
                "amnezia-wg-option",
                "amnezia-wg-options",
                "dialer-proxy",
                "dialer_proxy",
                "plugin",
                "plugin-opts",
                "plugin_opts",
                "tls",
                "reality-opts",
                "ws-opts",
                "grpc-opts",
                "xhttp-opts",
                "mux",
                "smux",
                "multiplex",
                "udp-over-tcp",
                "udp_over_tcp",
            ],
            false,
            "WireGuard wire extensions, TLS, stream wrappers and chaining are unsupported",
        )?;
    }
    let private_key = claim(mapping, None, &["private-key", "private_key"], key)?;
    let public_key = claim(mapping, peer, &["public-key", "public_key"], key)?;
    let preshared_key = claim(
        mapping,
        peer,
        &["pre-shared-key", "pre_shared_key", "preshared-key"],
        key,
    )?;
    let addresses = claim(
        mapping,
        None,
        &["local-address", "local_address", "address"],
        |value| {
            list(value)?
                .map(|value| parse_wireguard_addresses([value.as_str()]))
                .transpose()
        },
    )?
    .unwrap_or_default();
    let ip = fields::text_alias(mapping, &["ip"])?
        .map(|value| parse_wireguard_addresses([value.as_str()]))
        .transpose()?;
    let ipv6 = fields::text_alias(mapping, &["ipv6"])?
        .map(|value| parse_wireguard_addresses([value.as_str()]))
        .transpose()?;
    if ip.is_some_and(|(_, v6)| v6.is_some()) || ipv6.is_some_and(|(v4, _)| v4.is_some()) {
        return Err("WireGuard ip and ipv6 must match their declared address families");
    }
    let local_v4 = coalesce_equal(
        [Ok(addresses.0), Ok(ip.and_then(|(v4, _)| v4))],
        "WireGuard IPv4 address claims must agree",
    )?;
    let local_v6 = coalesce_equal(
        [Ok(addresses.1), Ok(ipv6.and_then(|(_, v6)| v6))],
        "WireGuard IPv6 address claims must agree",
    )?;
    let server = coalesce_equal(
        std::iter::once(mapping)
            .chain(peer)
            .map(|source| fields::optional_text_alias(source, &["server"])),
        "WireGuard endpoint claims must agree",
    )?
    .ok_or("WireGuard endpoint server is missing")?;
    let port = coalesce_equal(
        std::iter::once(mapping)
            .chain(peer)
            .map(|source| fields::u64_alias(source, &["port"])),
        "WireGuard endpoint port claims must agree",
    )?
    .and_then(|port| u16::try_from(port).ok())
    .filter(|port| *port != 0)
    .ok_or("WireGuard endpoint port is invalid")?;
    let keepalive = coalesce_equal(
        std::iter::once(mapping).chain(peer).map(|source| {
            fields::duration_alias(
                source,
                &[
                    "persistent-keepalive",
                    "persistent_keepalive",
                    "persistent_keepalive_interval",
                ],
            )
        }),
        "WireGuard keepalive claims must agree",
    )?
    .map(|value| u16::try_from(value).map_err(|_| "WireGuard keepalive must fit in 16-bit seconds"))
    .transpose()?;
    let mut config = WireGuardConfig {
        private_key,
        public_key,
        preshared_key,
        local_v4,
        local_v6,
        mtu: fields::u64_alias(mapping, &["mtu"])?
            .map(|mtu| u16::try_from(mtu).map_err(|_| "WireGuard MTU must fit in 16 bits"))
            .transpose()?
            .unwrap_or(1420),
        persistent_keepalive: keepalive,
        reserved: claim(mapping, peer, &["reserved"], reserved)?,
        ..WireGuardConfig::default()
    };
    if let Some(allowed_ips) = claim(mapping, peer, &["allowed-ips", "allowed_ips"], |value| {
        list(value)?
            .map(|value| parse_wireguard_allowed_ips(&value))
            .transpose()
    })? {
        config.allowed_ips = allowed_ips;
    }
    let network = fields::text_alias(mapping, &["network"])?;
    let network_udp = network
        .as_deref()
        .map(packet_network)
        .transpose()?
        .flatten();
    let udp = coalesce_equal(
        [Ok(network_udp), fields::bool_alias(mapping, &["udp"])],
        "WireGuard network conflicts with udp",
    )?;
    config.network = (udp == Some(false)).then(|| "tcp".into());
    config.normalize();
    config.check().map_err(|(_, message)| message)?;
    let mut node = Node {
        name: fields::optional_text_alias(mapping, &["name"])?
            .unwrap_or_else(|| format!("wireguard-{server}:{port}")),
        address: format!("{server}:{port}"),
        host: server,
        port,
        outbound: OutboundConfig::WireGuard(config),
        subscription_id,
        ..Node::default()
    };
    node.normalize_wireguard();
    node.validate()
        .map_err(|_| "invalid WireGuard endpoint settings")?;
    node.id = node.derive_id();
    Ok(node)
}
