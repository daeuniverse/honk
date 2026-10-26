use base64::Engine as _;
use honk_config::node::{Node, WireGuardKey, validate_node_collection};
use honk_config::types::NodeProtocol;
use serde_json::{Value, json};

fn key(byte: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([byte; 32])
}

fn uri(scheme: &str, private_key: &str, pairs: &[(&str, &str)]) -> String {
    let user = url::form_urlencoded::byte_serialize(private_key.as_bytes()).collect::<String>();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish();
    format!("{scheme}://{user}@peer.example:51820/?{query}#tunnel")
}

fn link(extra: &[(&str, &str)]) -> String {
    let public_key = key(2);
    let mut pairs = vec![
        ("publickey", public_key.as_str()),
        ("address", "10.20.30.4/24,fd00::2/64"),
    ];
    pairs.extend_from_slice(extra);
    uri("wireguard", &key(1), &pairs)
}

fn flat_value() -> Value {
    json!({
        "name":"tunnel", "protocol":"wireguard", "host":"peer.example", "address":"peer.example:51820", "port":51820,
        "wg_private_key":key(1), "wg_public_key":key(2), "wg_addresses":["10.20.30.4/24", "fd00::2/64"],
    })
}

fn flat(value: Value) -> Result<Node, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn wireguard_uris_and_flat_nodes_share_one_canonical_model() {
    let node = Node::from_share_link(&link(&[])).unwrap();
    assert_eq!(node.protocol(), NodeProtocol::WireGuard);
    assert_eq!(node.wireguard().unwrap().private_key_bytes(), &[1; 32]);
    assert_eq!(node.wireguard().unwrap().public_key_bytes(), &[2; 32]);
    assert_eq!(
        node.wireguard().unwrap().local_v4.unwrap().to_string(),
        "10.20.30.4"
    );
    assert_eq!(
        node.wireguard().unwrap().local_v6.unwrap().to_string(),
        "fd00::2"
    );
    assert_eq!(node.wireguard().unwrap().mtu, 1420);
    assert_eq!(
        node.wireguard()
            .unwrap()
            .allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["0.0.0.0/0", "::/0"]
    );
    let from_flat = flat(flat_value()).unwrap();
    assert_eq!(from_flat.derive_id(), node.id);
    assert_eq!(from_flat.outbound, node.outbound);
    let public_key = key(2);
    let hiddify = format!(
        "wg://peer.example:51820/?{}#another-name",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("pk", key(1)),
                ("peer_pk", public_key),
                ("local_address", "10.20.30.4/32,fd00::2/128".into())
            ])
            .finish()
    );
    let hiddify = Node::from_share_link(&hiddify).unwrap();
    assert_eq!(hiddify.outbound, node.outbound);
    assert_eq!(hiddify.id, node.id);
}

#[test]
fn decoded_keys_aliases_and_zero_values_have_one_identity() {
    let bytes = [251; 32];
    let standard = base64::engine::general_purpose::STANDARD.encode(bytes);
    let alternative = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let original = Node::from_share_link(&uri(
        "wireguard",
        &standard,
        &[("publickey", &standard), ("address", "10.0.0.2/32")],
    ))
    .unwrap();
    let variants = [
        uri(
            "wg",
            &alternative,
            &[
                ("publicKey", &alternative),
                ("public-key", &standard),
                ("address", "10.0.0.2/24"),
            ],
        ),
        format!(
            "wg://{}@peer.example:51820?publickey={standard}&address=10.0.0.2",
            url::form_urlencoded::byte_serialize(standard.as_bytes()).collect::<String>()
        ),
    ];
    for variant in variants {
        let parsed = Node::from_share_link(&variant).unwrap();
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.wireguard().unwrap().private_key_bytes(), &bytes);
    }
    let parsed: WireGuardKey = alternative.parse().unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), json!(standard));
    assert!(!format!("{parsed:?}").contains(&alternative));
    let normal = Node::from_share_link(&link(&[])).unwrap();
    let zero = Node::from_share_link(&link(&[
        ("reserved", "0,0,0"),
        ("keepalive", "0"),
        ("presharedkey", &key(0)),
    ]))
    .unwrap();
    assert_eq!(normal.outbound, zero.outbound);
    assert_eq!(normal.id, zero.id);
}

#[test]
fn reserved_psk_routes_keepalive_and_udp_survive_flat_roundtrips() {
    let node = Node::from_share_link(&link(&[
        ("presharedkey", &key(3)),
        ("reserved", "1,2,255"),
        ("keepalive", "25"),
        ("mtu", "1400"),
        ("allowedips", "2001:db8::42/64,10.4.5.99/24,10.4.5.0/24"),
        ("udp", "false"),
    ]))
    .unwrap();
    let config = node.wireguard().unwrap();
    assert_eq!(config.preshared_key_bytes(), Some(&[3; 32]));
    assert_eq!(config.reserved, Some([1, 2, 255]));
    assert_eq!(config.persistent_keepalive, Some(25));
    assert_eq!(config.mtu, 1400);
    assert_eq!(
        config
            .allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.4.5.0/24", "2001:db8::/64"]
    );
    assert_eq!(node.network(), Some("tcp"));
    let base64_reserved = Node::from_share_link(&link(&[
        ("reserved", "AQL/"),
        ("presharedkey", &key(3)),
        ("mtu", "1400"),
        ("keepalive", "25"),
        ("allowedips", "10.4.5.0/24,2001:db8::/64"),
        ("udp", "0"),
    ]))
    .unwrap();
    assert_eq!(base64_reserved.id, node.id);
    for roundtrip in [
        serde_json::from_str::<Node>(&serde_json::to_string(&node).unwrap()).unwrap(),
        serde_yaml::from_str::<Node>(&serde_yaml::to_string(&node).unwrap()).unwrap(),
        toml::from_str::<Node>(&toml::to_string(&node).unwrap()).unwrap(),
    ] {
        assert_eq!(roundtrip.outbound, node.outbound);
        assert_eq!(roundtrip.id, node.id);
    }
}

#[test]
fn identity_separates_authenticated_dial_shape_from_tuning_and_metadata() {
    let node = Node::from_share_link(&link(&[])).unwrap();
    let changes: &[fn(&mut Node)] = &[
        |node| node.host = "other.example".into(),
        |node| node.port = 51821,
        |node| node.wireguard_mut().unwrap().private_key = Some(key(9).parse().unwrap()),
        |node| node.wireguard_mut().unwrap().public_key = Some(key(9).parse().unwrap()),
        |node| node.wireguard_mut().unwrap().preshared_key = Some(key(9).parse().unwrap()),
        |node| node.wireguard_mut().unwrap().local_v4 = Some("10.20.30.5".parse().unwrap()),
        |node| node.wireguard_mut().unwrap().local_v6 = None,
        |node| node.wireguard_mut().unwrap().reserved = Some([1, 2, 3]),
        |node| node.wireguard_mut().unwrap().allowed_ips = vec!["10.0.0.0/8".parse().unwrap()],
        |node| node.wireguard_mut().unwrap().network = Some("tcp".into()),
    ];
    for change in changes {
        let mut other = node.clone();
        change(&mut other);
        assert!(other.validate().is_ok());
        assert_ne!(other.derive_id(), node.id);
    }
    let mut tuning = node.clone();
    tuning.name = "renamed".into();
    tuning.tags.push("tag".into());
    tuning.mark = Some(7);
    tuning.subscription_id = Some(uuid::Uuid::new_v4());
    tuning.wireguard_mut().unwrap().mtu = 1280;
    tuning.wireguard_mut().unwrap().persistent_keepalive = Some(25);
    assert_eq!(tuning.derive_id(), node.id);
    for network in ["udp", "tcp,udp", "TCP, UDP"] {
        let mut other = node.clone();
        other.wireguard_mut().unwrap().network = Some(network.into());
        other.validate().unwrap();
        assert_eq!(other.derive_id(), node.id);
    }
}

#[test]
fn mtu_limits_follow_the_configured_local_family_and_do_not_silently_default() {
    for (addresses, minimum) in [
        (json!(["10.0.0.2/32"]), 576),
        (json!(["fd00::2/128"]), 1280),
    ] {
        for mtu in [minimum, 1420, 65535] {
            let mut value = flat_value();
            value["wg_addresses"] = addresses.clone();
            value["wg_mtu"] = json!(mtu);
            assert_eq!(
                u32::from(flat(value).unwrap().wireguard().unwrap().mtu),
                mtu
            );
        }
        for mtu in [0, minimum - 1, 65536] {
            let mut value = flat_value();
            value["wg_addresses"] = addresses.clone();
            value["wg_mtu"] = json!(mtu);
            assert!(flat(value).is_err(), "{mtu}");
        }
    }
}

#[test]
fn malformed_keys_addresses_routes_and_peer_shapes_are_rejected_safely() {
    for (parameter, value, field) in [
        ("publickey", "not-a-key", "wg_public_key"),
        ("presharedkey", "AA==", "wg_preshared_key"),
        ("address", "10.0.0.2/33", "wg_addresses"),
        ("address", "fd00::2/129", "wg_addresses"),
        ("address", "10.0.0.2,10.0.0.3", "wg_addresses"),
        ("address", "fd00::2,fd00::2", "wg_addresses"),
        ("address", "", "wg_addresses"),
        ("allowedips", "", "wg_allowed_ips"),
        ("allowedips", "10.0.0.0/33", "wg_allowed_ips"),
        ("reserved", "1,2", "wg_reserved"),
        ("reserved", "1,2,256", "wg_reserved"),
        ("reserved", "AQI=", "wg_reserved"),
        ("mtu", "1279", "wg_mtu"),
        ("mtu", "65536", "wg_mtu"),
        ("keepalive", "65536", "wg_keepalive"),
        ("keepalive", "-1", "wg_keepalive"),
        ("udp", "maybe", "network"),
    ] {
        let bad = link(&[(parameter, value)]);
        let mut diagnostics = Vec::new();
        let error =
            Node::from_share_link_with_detailed_diagnostics(&bad, &mut diagnostics).unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-config-value");
        assert_eq!(
            error.diagnostic.setting.to_string(),
            format!("nodes.{field}")
        );
        let rendered = format!("{error:?} {diagnostics:?}");
        assert!(!rendered.contains("peer.example"));
        assert!(!rendered.contains(&key(1)));
    }
    for field in ["wg_private_key", "wg_public_key"] {
        let mut value = flat_value();
        value.as_object_mut().unwrap().remove(field);
        assert!(flat(value).is_err());
        for invalid in [
            key(1).replace('=', "=="),
            "PRIVATE_SECRET".into(),
            base64::engine::general_purpose::STANDARD.encode([1; 31]),
        ] {
            let mut value = flat_value();
            value[field] = json!(invalid);
            assert!(flat(value).is_err());
        }
    }
    for query in ["peers", "jc"] {
        assert!(Node::from_share_link(&link(&[(query, "1")])).is_err());
    }
    for bad in [
        "wg://peer.example:51820?address=10.0.0.2",
        "wg://peer.example?address=10.0.0.2",
        "wg://peer.example:0?address=10.0.0.2",
    ] {
        assert!(Node::from_share_link(bad).is_err());
    }
}

#[test]
fn shared_admission_rejects_missing_keys_and_noncanonical_routes() {
    let node = Node::from_share_link(&link(&[])).unwrap();
    let mut incomplete = node.clone();
    incomplete.wireguard_mut().unwrap().public_key = None;
    let error = validate_node_collection(&[incomplete]).unwrap_err();
    assert_eq!(
        error.diagnostic.setting.to_string(),
        "nodes[1].wg_public_key"
    );
    let mut noncanonical = node;
    noncanonical.wireguard_mut().unwrap().allowed_ips = vec!["10.0.0.1/24".parse().unwrap()];
    assert!(noncanonical.validate_protocol().is_err());
    noncanonical.wireguard_mut().unwrap().normalize();
    noncanonical.id = noncanonical.derive_id();
    validate_node_collection(&[noncanonical]).unwrap();
}

#[test]
fn wireguard_endpoint_spellings_normalize_without_changing_other_protocol_ids() {
    let node = Node::from_share_link(&link(&[])).unwrap();
    let mut upper = flat_value();
    upper["host"] = json!("PEER.EXAMPLE");
    assert_eq!(flat(upper).unwrap().derive_id(), node.id);
    let mut numeric = flat_value();
    numeric["host"] = json!("2001:0DB8:0:0:0:0:0:1");
    let numeric = flat(numeric).unwrap();
    let uri = link(&[]).replace("peer.example", "[2001:db8::1]");
    assert_eq!(numeric.derive_id(), Node::from_share_link(&uri).unwrap().id);
    assert_eq!(numeric.host, "2001:db8::1");
    let mut bad = node;
    bad.wireguard_mut().unwrap().network = Some("tcp,quic".into());
    assert!(bad.validate_protocol().is_err());
}

#[test]
fn flat_wireguard_does_not_silently_ignore_peer_collections() {
    for peers in [Value::Null, json!([]), json!([{}]), json!([{}, {}])] {
        for field in ["peers", "wg_peers"] {
            let mut value = flat_value();
            value[field] = peers.clone();
            assert!(flat(value).is_err());
        }
    }
}

#[test]
fn wireguard_preserves_address_only_ipv6_rejection_before_host_normalization() {
    let mut value = flat_value();
    value["host"] = json!("");
    value["address"] = json!("[2001:db8::1]:51820");
    assert!(flat(value).is_err());
    let mut ipv4 = flat_value();
    ipv4["host"] = json!("");
    ipv4["address"] = json!("192.0.2.1:51820");
    let ipv4 = flat(ipv4).unwrap();
    assert_eq!(ipv4.host, "192.0.2.1");
}

#[test]
fn wireguard_uri_keeps_the_shared_incompatible_plugin_rejection() {
    for field in ["plugin", "plugin-opts", "plugin_opts"] {
        for value in ["", "obfs-local"] {
            assert!(Node::from_share_link(&link(&[(field, value)])).is_err());
        }
    }
}
