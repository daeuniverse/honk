//! Proxy chain nodes: `node { name: a -> b }`.

use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::node::{Node, OutboundConfig};
use honk_config::parser::parse_dae_config_with_detailed_diagnostics;
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
    let mut node = Node {
        name: name.into(),
        outbound: OutboundConfig::Chain {
            hops: hops.iter().map(|hop| hop.to_string()).collect(),
        },
        ..Node::default()
    };
    node.id = node.derive_id();
    node
}

#[test]
fn two_and_three_hop_chains_parse_in_entry_to_exit_order() {
    let (config, diagnostics) = parse(&format!(
        " front: '{SOCKS}'\n mid: '{SS}'\n land: '{TROJAN}'\n via: front -> land\n far: front->mid -> land\n"
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
    assert_eq!(via.id, via.derive_id());
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
fn identity_follows_protocol_and_ordered_hops_only() {
    let base = chain_node("via", &["a", "b"]);
    assert_eq!(base.id, chain_node("renamed", &["a", "b"]).id);
    assert_ne!(base.id, chain_node("via", &["b", "a"]).id);
    assert_ne!(base.id, chain_node("via", &["a", "c"]).id);
    assert_ne!(base.id, chain_node("via", &["a", "b", "c"]).id);
    assert_ne!(
        chain_node("via", &["a|b", "c"]).id,
        chain_node("via", &["a", "b|c"]).id
    );
    // Pinned so an accidental change to identity material is noticed.
    assert_eq!(base.id.to_string(), "10002d11-ee0e-5576-a7d2-f4b258ad02f1");
}

#[test]
fn structured_formats_round_trip_hops() {
    let node = chain_node("via", &["front", "hk: east", "land"]);
    let json = serde_json::to_value(&node).unwrap();
    assert_eq!(json["protocol"], "chain");
    assert_eq!(
        json["hops"],
        serde_json::json!(["front", "hk: east", "land"])
    );
    let from_json: Node = serde_json::from_value(json).unwrap();
    let from_yaml: Node = serde_yaml::from_str(&serde_yaml::to_string(&node).unwrap()).unwrap();
    let from_toml: Node = toml::from_str(&toml::to_string(&node).unwrap()).unwrap();
    for decoded in [from_json, from_yaml, from_toml] {
        assert_eq!(decoded.outbound, node.outbound);
        assert_eq!(decoded.id, node.id);
    }
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
