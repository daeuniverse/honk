//! Proxy chain nodes: `node { name: a -> b }`.

use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::node::{Group, Node, validate_node_collection};
use honk_config::parser::{parse_dae_config_with_detailed_diagnostics, resolve_group_filters};
use honk_config::types::NodeProtocol;

const SOCKS: &str = "socks5://127.0.0.1:1080";
const SS: &str = "ss://YWVzLTEyOC1nY206cGFzcw@ss.example:8388";
const TROJAN: &str = "trojan://secret@trojan.example:443";

fn dae(nodes: &str) -> String {
    format!("node {{\n{nodes}\n}}\nrouting {{\n fallback: direct\n}}\n")
}

fn parse(nodes: &str) -> Result<(Config, Vec<DetailedDiagnostic>), Vec<DetailedDiagnostic>> {
    let mut diagnostics = Vec::new();
    match parse_dae_config_with_detailed_diagnostics(&dae(nodes), &mut diagnostics) {
        Ok(config) => Ok((config, diagnostics)),
        Err(_) => Err(diagnostics),
    }
}

fn chain<'a>(config: &'a Config, name: &str) -> &'a Node {
    config
        .nodes
        .iter()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("no node named {name}"))
}

fn chain_node(name: &str, hops: &[&str]) -> Node {
    Node::chain(name, hops.iter().map(|hop| hop.to_string()).collect())
}

#[test]
fn two_to_four_hop_chains_parse_in_entry_to_exit_order() {
    let (config, diagnostics) = parse(&format!(
        " front: '{SOCKS}'\n mid: '{SS}'\n land: '{TROJAN}'\n spare: 'socks5://127.0.0.1:1081'\n via: front -> land\n far: front->mid -> land\n furthest: front -> mid -> spare -> land\n"
    ))
    .unwrap();
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let via = chain(&config, "via");
    assert_eq!(via.protocol(), NodeProtocol::Chain);
    assert_eq!(via.chain_hops().unwrap(), ["front", "land"]);
    assert!(via.host.is_empty() && via.address.is_empty() && via.port == 0);
    assert_eq!(
        chain(&config, "far").chain_hops().unwrap(),
        ["front", "mid", "land"]
    );
    assert_eq!(
        chain(&config, "furthest").chain_hops().unwrap(),
        ["front", "mid", "spare", "land"]
    );
    assert!(via.id.is_nil() && via.derive_id().is_nil());
    assert!(via.resolved_chain_hops().is_none());
}

#[test]
fn quoted_hop_names_keep_spaces_colons_and_arrows() {
    let (config, _) = parse(&format!(
        " 'hk: east': '{SOCKS}'\n 'a->b': '{TROJAN}'\n 'via hk': 'hk: east' -> 'a->b'\n"
    ))
    .unwrap();
    assert_eq!(
        chain(&config, "via hk").chain_hops().unwrap(),
        ["hk: east", "a->b"]
    );
}

#[test]
fn unquoted_hop_names_may_hold_colons_and_inner_spaces() {
    let (config, _) = parse(&format!(
        " 'front:8080': '{SOCKS}'\n 'hk east': '{TROJAN}'\n via: front:8080 -> hk east\n"
    ))
    .unwrap();
    assert_eq!(
        chain(&config, "via").chain_hops().unwrap(),
        ["front:8080", "hk east"]
    );
}

#[test]
fn a_value_without_an_arrow_is_a_dropped_link_not_a_chain() {
    let (config, diagnostics) = parse(&format!(" front: '{SOCKS}'\n via: front\n")).unwrap();
    assert!(config.nodes.iter().all(|node| node.name != "via"));
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "invalid-node-entry"),
        "{diagnostics:?}"
    );
}

#[test]
fn share_link_with_an_arrow_in_its_fragment_stays_a_link() {
    let (config, _) = parse(&format!(" land: {TROJAN}#hk->jp\n")).unwrap();
    assert_eq!(chain(&config, "land").protocol(), NodeProtocol::Trojan);
}

#[test]
fn malformed_chains_are_rejected() {
    for (nodes, setting, message) in [
        (
            " via: front ->\n",
            "nodes[1].hops",
            "chain hop names must not be empty",
        ),
        (
            " via: -> front\n",
            "nodes[1].hops",
            "chain hop names must not be empty",
        ),
        (
            " via: front -> via\n",
            "nodes[1].hops",
            "chain node must not use itself as a hop",
        ),
        (
            " via: a -> b -> c -> d -> e\n",
            "nodes[1].hops",
            "chain node allows at most four hops",
        ),
        (
            " front -> land\n",
            "nodes[1].name",
            "node name must not be empty",
        ),
    ] {
        let diagnostics = parse(nodes).expect_err(nodes);
        assert!(
            diagnostics.iter().any(|diagnostic| diagnostic.terminal
                && diagnostic.setting.to_string() == setting
                && diagnostic.message == message),
            "{nodes:?}: {diagnostics:?}"
        );
    }
}

#[test]
fn intrinsic_checks_bound_hops_and_endpoint() {
    assert!(chain_node("via", &["a", "b"]).validate().is_ok());
    assert!(chain_node("via", &["a", "b", "c", "d"]).validate().is_ok());
    assert!(chain_node("via", &["a"]).validate().is_err());
    assert!(
        chain_node("via", &["a", "b", "c", "d", "e"])
            .validate()
            .is_err()
    );
    assert!(chain_node("via", &["a", " "]).validate().is_err());
    assert!(chain_node("via", &["a", "via"]).validate().is_err());
    assert!(chain_node("", &["a", "b"]).validate().is_err());
    let mut addressed = chain_node("via", &["a", "b"]);
    addressed.host = "example.com".into();
    addressed.port = 443;
    assert!(addressed.validate().is_err());
}

#[test]
fn checked_constructor_refuses_invalid_hops() {
    let front = Node::from_share_link(&format!("{SOCKS}#front")).unwrap();
    let mut land = Node::from_share_link(&format!("{TROJAN}#land")).unwrap();
    assert!(Node::chain_from_nodes("via", &[]).is_err());
    assert!(Node::chain_from_nodes("via", &[&front; 5]).is_err());
    assert!(Node::chain_from_nodes("via", &[&front, &Config::builtin_direct_node()]).is_err());
    land.id = front.id;
    let error = Node::chain_from_nodes("via", &[&front, &land]).unwrap_err();
    assert_eq!(error.diagnostic.code, "noncanonical-node-id");
}

#[test]
fn identity_follows_physical_contents_and_hop_order() {
    let assemble = |source: String| {
        parse(&source)
            .unwrap()
            .0
            .assemble(resolve_group_filters)
            .unwrap()
    };
    let original = assemble(format!(
        " front: '{SOCKS}'\n land: '{TROJAN}'\n via: front -> land"
    ));
    let renamed_hop = assemble(format!(
        " via: 'front|new' -> land\n land: '{TROJAN}'\n 'front|new': '{SOCKS}'"
    ));
    let renamed_chain = assemble(format!(
        " front: '{SOCKS}'\n land: '{TROJAN}'\n renamed: front -> land"
    ));
    let reversed = assemble(format!(
        " front: '{SOCKS}'\n land: '{TROJAN}'\n via: land -> front"
    ));
    let replaced = assemble(format!(
        " front: '{SOCKS}'\n land: 'trojan://different@trojan.example:443'\n via: front -> land"
    ));
    let extended = assemble(format!(
        " front: '{SOCKS}'\n mid: '{SS}'\n land: '{TROJAN}'\n via: front -> mid -> land"
    ));

    let base = chain(&original, "via");
    assert!(!base.id.is_nil());
    assert_eq!(base.id, base.derive_id());
    assert_eq!(base.id, chain(&renamed_hop, "via").id);
    assert_eq!(base.id, chain(&renamed_chain, "renamed").id);
    assert_ne!(base.id, chain(&reversed, "via").id);
    assert_ne!(base.id, chain(&replaced, "via").id);
    assert_ne!(base.id, chain(&extended, "via").id);
    assert_eq!(
        chain(&original, "front").id,
        chain(&renamed_hop, "front|new").id
    );
    assert_ne!(chain(&original, "land").id, chain(&replaced, "land").id);
}

#[test]
fn structured_formats_round_trip_hops() {
    let front = Node::from_share_link(&format!("{SOCKS}#front")).unwrap();
    let middle = Node::from_share_link(&format!("{SS}#middle")).unwrap();
    let mut land = Node::from_share_link(TROJAN).unwrap();
    land.name = "hk: east".into();
    let node = Node::chain_from_nodes("via", &[&front, &land, &middle]).unwrap();
    let json = serde_json::to_value(&node).unwrap();
    assert_eq!(json["protocol"], "chain");
    assert_eq!(
        json["hops"],
        serde_json::json!(["front", "hk: east", "middle"])
    );
    assert!(json.get("resolved").is_none());
    let from_json: Node = serde_json::from_value(json).unwrap();
    let from_yaml: Node = serde_yaml::from_str(&serde_yaml::to_string(&node).unwrap()).unwrap();
    let from_toml: Node = toml::from_str(&toml::to_string(&node).unwrap()).unwrap();
    for decoded in [from_json, from_yaml, from_toml] {
        assert_eq!(decoded.chain_hops(), node.chain_hops());
        assert!(decoded.resolved_chain_hops().is_none());
        assert!(decoded.derive_id().is_nil());
        assert_ne!(decoded, node);
        assert_eq!(decoded.id, node.id);
    }
}

#[test]
fn structured_explicit_member_follows_the_rebound_chain_in_each_format() {
    let (mut source, _) = parse(&format!(
        " via: front -> land\n front: '{SOCKS}'\n land: '{TROJAN}'"
    ))
    .unwrap();
    // Normalization must keep the two distinct source aliases distinct.
    let stored_chain = source.nodes[1].id;
    let stored_front = uuid::Uuid::from_u128(43);
    source.nodes[0].id = stored_chain;
    source.nodes[1].id = stored_front;
    source.groups.push(Group {
        name: "chosen".into(),
        nodes: vec![stored_chain, stored_front, stored_chain],
        groups: vec!["fallback".into()],
        ..Default::default()
    });
    source.groups.push(Group {
        name: "fallback".into(),
        filters: vec!["name(land)".into()],
        ..Default::default()
    });
    let directory = tempfile::tempdir().unwrap();
    for format in ["json", "yaml", "toml"] {
        let path = directory.path().join(format!("config.{format}"));
        source.to_file(path.to_str().unwrap()).unwrap();
        let partial = Config::from_file(path.to_str().unwrap()).unwrap();
        partial.validate_detailed().unwrap();
        assert!(chain(&partial, "via").resolved_chain_hops().is_none());
        let config = partial.assemble(resolve_group_filters).unwrap();
        let front = chain(&config, "front").id;
        let via = chain(&config, "via");
        let land = chain(&config, "land").id;
        assert_eq!(via.resolved_chain_hops().unwrap(), [front, land]);
        assert_eq!(config.groups[0].nodes, [via.id, front]);
        assert_eq!(config.groups[1].nodes, [land]);
        assert_eq!(front, stored_chain);
        assert_ne!(via.id, stored_chain);
        assert_ne!(front, stored_front);
    }
}

#[test]
fn structured_ambiguous_chain_alias_rejects_explicit_membership() {
    let (mut source, _) = parse(&format!(
        " via: front -> land\n front: '{SOCKS}'\n land: '{TROJAN}'"
    ))
    .unwrap();
    let alias = source.nodes[1].id;
    source.nodes[0].id = alias;
    source.groups.push(Group {
        name: "chosen".into(),
        nodes: vec![alias],
        ..Default::default()
    });
    let mut diagnostics = Vec::new();
    let error = Config::from_json_str_with_detailed_diagnostics(
        &source.to_json_string().unwrap(),
        &mut diagnostics,
    )
    .unwrap_err();
    assert_eq!(error.diagnostic.code, "ambiguous-group-node-reference");
    assert_eq!(error.diagnostic.setting.to_string(), "groups[1].nodes[1]");
}

#[test]
fn ordinary_nodes_do_not_serialize_hops() {
    let node = Node::from_share_link(SOCKS).unwrap();
    let json = serde_json::to_value(&node).unwrap();
    assert!(json.get("hops").is_none());
    let mut with_hops = json;
    with_hops["hops"] = serde_json::json!(["a", "b"]);
    let decoded: Node = serde_json::from_value(with_hops).unwrap();
    assert_eq!(decoded.outbound, node.outbound);
}

mod assembled {
    use super::*;

    const HY2: &str = "hysteria2://auth@hy2.example:443";
    const VISION: &str = "vless://00000000-0000-4000-8000-000000000001@vless.example:443?security=tls&flow=xtls-rprx-vision";

    fn rejection(nodes: &str) -> DetailedDiagnostic {
        let (config, _) = parse(nodes).unwrap();
        *config
            .assemble(resolve_group_filters)
            .unwrap_err()
            .diagnostic
    }

    #[test]
    fn valid_chains_pass_with_any_first_hop() {
        for front in [SOCKS, HY2, VISION] {
            let (config, _) = parse(&format!(
                " front: '{front}'\n mid: '{SS}'\n land: '{TROJAN}'\n via: front -> mid -> land\n"
            ))
            .unwrap();
            let config = config.assemble(resolve_group_filters).unwrap();
            config.validate_assembled().unwrap();
        }
    }

    #[test]
    fn hops_resolve_to_node_ids_entry_first() {
        let (config, _) = parse(&format!(
            " via: land -> front\n front: '{SOCKS}'\n land: '{TROJAN}'\n back: front -> land\n"
        ))
        .unwrap();
        let config = config.assemble(resolve_group_filters).unwrap();
        let front = chain(&config, "front").id;
        let land = chain(&config, "land").id;
        assert_eq!(
            chain(&config, "via").resolved_chain_hops().unwrap(),
            [land, front]
        );
        assert_eq!(
            chain(&config, "back").resolved_chain_hops().unwrap(),
            [front, land]
        );
        assert!(chain(&config, "front").resolved_chain_hops().is_none());
    }

    #[test]
    fn partial_collections_defer_multiple_chains_and_reject_final_duplicates() {
        let (mut config, _) = parse(&format!(
            " via: front -> land\n far: land -> front\n front: '{SOCKS}'"
        ))
        .unwrap();
        config.validate_detailed().unwrap();
        assert!(chain(&config, "via").id.is_nil() && chain(&config, "far").id.is_nil());
        let mut land = Node::from_share_link(TROJAN).unwrap();
        land.name = "land".into();
        config.nodes.push(land);
        config.groups.push(Group {
            name: "chosen".into(),
            filters: vec!["name(via)".into()],
            ..Default::default()
        });
        let bound = config.clone().assemble(resolve_group_filters).unwrap();
        assert_eq!(bound.groups[0].nodes, [chain(&bound, "via").id]);

        config
            .nodes
            .push(chain_node("duplicate", &["front", "land"]));
        config.validate_detailed().unwrap();
        let error = config
            .assemble(|_, _, _| panic!("members rebuilt before ID admission"))
            .unwrap_err();
        assert_eq!(error.diagnostic.code, "duplicate-node-id");
    }

    #[test]
    fn direct_admission_rejects_stale_bound_and_serialized_hops() {
        let (partial, _) = parse(&format!(
            " via: front -> land\n front: '{SOCKS}'\n land: '{TROJAN}'"
        ))
        .unwrap();
        let bound = partial.assemble(resolve_group_filters).unwrap();
        validate_node_collection(&bound.nodes).unwrap();

        let mut stale = bound.clone();
        stale.nodes[2] = Node::from_share_link("trojan://new@trojan.example:443#land").unwrap();
        let error = validate_node_collection(&stale.nodes).unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-chain-binding");
        let rebound = stale.assemble(resolve_group_filters).unwrap();
        assert_ne!(rebound.nodes[0].id, bound.nodes[0].id);

        let mut serialized = bound.clone();
        serialized.nodes[0] =
            serde_json::from_value(serde_json::to_value(&bound.nodes[0]).unwrap()).unwrap();
        assert_eq!(serialized.nodes[0].id, bound.nodes[0].id);
        assert_ne!(serialized, bound);
        let error = validate_node_collection(&serialized.nodes).unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-chain-binding");
        assert_eq!(serialized.assemble(resolve_group_filters).unwrap(), bound);
    }

    #[test]
    fn missing_hop_is_rejected() {
        let error = rejection(&format!(" front: '{SOCKS}'\n via: front -> land\n"));
        assert_eq!(error.code, "invalid-chain-hop-reference");
        assert_eq!(error.setting.to_string(), "nodes[2].hops[2]");
    }

    #[test]
    fn duplicate_hop_name_is_rejected() {
        let error = rejection(&format!(
            " front: '{SOCKS}'\n land: '{TROJAN}'\n land: '{SS}'\n via: front -> land\n"
        ));
        assert_eq!(error.code, "ambiguous-chain-hop-reference");
    }

    #[test]
    fn builtins_and_chains_cannot_be_hops() {
        for hops in [
            "direct -> land",
            "front -> block",
            "inner -> land",
            "front -> inner",
        ] {
            let error = rejection(&format!(
                " front: '{SOCKS}'\n land: '{TROJAN}'\n inner: front -> land\n via: {hops}\n"
            ));
            assert_eq!(error.code, "unsupported-chain-hop", "{hops}");
        }
    }

    #[test]
    fn later_hops_must_support_tunneled_dial() {
        for exit in [HY2, VISION, "anytls://secret@anytls.example:443"] {
            let error = rejection(&format!(
                " front: '{SOCKS}'\n land: '{exit}'\n via: front -> land\n"
            ));
            assert_eq!(error.code, "unsupported-chain-hop", "{exit}");
            assert_eq!(error.setting.to_string(), "nodes[3].hops[2]");
        }
    }

    #[test]
    fn ech_discovery_depends_on_the_hop_position_and_effective_tls_name() {
        for (link, allowed_as_exit) in [
            ("trojan://p@land.test:443?ech=1", false),
            (
                "trojan://p@127.0.0.1:443?ech=1&type=ws&host=land.test",
                false,
            ),
            ("trojan://p@land.test:443?ech=1&sni=127.0.0.1", true),
            ("trojan://p@land.test:443?ech_config=QUJDMTIz", true),
        ] {
            let nodes = format!(" peer: '{link}'\n socks: '{SOCKS}'\n");
            let (front, _) = parse(&format!("{nodes} via: peer -> socks\n")).unwrap();
            front.assemble(resolve_group_filters).unwrap();
            let (exit, _) = parse(&format!("{nodes} via: socks -> peer\n")).unwrap();
            let result = exit.assemble(resolve_group_filters);
            if allowed_as_exit {
                result.unwrap();
            } else {
                let diagnostic = result.unwrap_err().diagnostic;
                assert_eq!(diagnostic.code, "unsupported-chain-hop");
                assert_eq!(diagnostic.setting.to_string(), "nodes[3].hops[2]");
            }
        }
    }
}
