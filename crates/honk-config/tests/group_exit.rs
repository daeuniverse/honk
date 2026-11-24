//! Group `exit`: every connection through the group leaves from one node.

use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::error::DetailedConfigError;
use honk_config::group::Group;
use honk_config::parser::{parse_dae_config, resolve_group_filters};

const SOCKS: &str = "socks5://127.0.0.1:1080";
const SS: &str = "ss://YWVzLTEyOC1nY206cGFzcw@ss.example:8388";
const TROJAN: &str = "trojan://secret@trojan.example:443";
const HY2: &str = "hysteria2://auth@hy2.example:443";

fn config(nodes: &str, exit: &str) -> Config {
    parse_dae_config(&format!(
        "node {{\n{nodes}\n}}\ngroup {{\n other {{\n  filter: name(front)\n  policy: fixed(0)\n }}\n proxy {{\n  filter: name(front)\n  policy: fixed(0)\n  exit: {exit}\n }}\n}}\nrouting {{\n fallback: proxy\n}}\n"
    ))
    .unwrap()
}

fn group<'a>(config: &'a Config, name: &str) -> &'a Group {
    config
        .groups
        .iter()
        .find(|group| group.name == name)
        .unwrap()
}

fn admit(mut partial: Config) -> Result<(), DetailedConfigError> {
    match partial.clone().assemble(resolve_group_filters) {
        Ok(config) => config.validate_assembled(),
        Err(error) => {
            // Bind and rebuild with the exits temporarily removed, then
            // verify the same exit refusal when checking an immutable snapshot.
            let exits: Vec<_> = partial
                .groups
                .iter_mut()
                .map(|group| group.exit.take())
                .collect();
            let mut assembled = partial.assemble(resolve_group_filters).unwrap();
            for (group, exit) in assembled.groups.iter_mut().zip(exits) {
                group.exit = exit;
            }
            let immutable = assembled.validate_assembled().unwrap_err();
            assert_eq!(immutable.diagnostic.code, error.diagnostic.code);
            assert_eq!(immutable.diagnostic.setting, error.diagnostic.setting);
            assert_eq!(
                immutable.diagnostic.entry_index,
                error.diagnostic.entry_index
            );
            Err(error)
        }
    }
}

fn rejection(nodes: &str, exit: &str) -> DetailedDiagnostic {
    *admit(config(nodes, exit)).unwrap_err().diagnostic
}

#[test]
fn exit_parses_and_validates() {
    let config = config(&format!(" front: '{SOCKS}'\n land: '{TROJAN}'\n"), "land");
    assert_eq!(group(&config, "proxy").exit.as_deref(), Some("land"));
    assert_eq!(group(&config, "other").exit, None);
    admit(config).unwrap();
}

#[test]
fn structured_formats_carry_exit_only_when_set() {
    let config = config(&format!(" front: '{SOCKS}'\n land: '{SS}'\n"), "'land'");
    let proxy = serde_json::to_value(group(&config, "proxy")).unwrap();
    assert_eq!(proxy["exit"], "land");
    let other = serde_json::to_value(group(&config, "other")).unwrap();
    assert!(other.get("exit").is_none());
    let decoded: Group = serde_json::from_value(proxy).unwrap();
    assert_eq!(decoded.exit.as_deref(), Some("land"));
    let decoded: Group = serde_yaml::from_str("name: proxy\nexit: land\n").unwrap();
    assert_eq!(decoded.exit.as_deref(), Some("land"));
}

#[test]
fn unknown_and_ambiguous_exits_are_rejected() {
    let error = rejection(&format!(" front: '{SOCKS}'\n"), "land");
    assert_eq!(error.code, "invalid-group-exit-target");
    assert_eq!(error.setting.to_string(), "groups[2].exit");
    let error = rejection(
        &format!(" front: '{SOCKS}'\n land: '{TROJAN}'\n land: '{SS}'\n"),
        "land",
    );
    assert_eq!(error.code, "ambiguous-group-exit-target");
}

#[test]
fn groups_chains_and_builtins_cannot_be_exits() {
    for exit in ["other", "direct", "block", "via"] {
        let error = rejection(
            &format!(" front: '{SOCKS}'\n land: '{TROJAN}'\n via: front -> land\n"),
            exit,
        );
        assert_eq!(error.code, "unsupported-group-exit-target", "{exit}");
    }
}

#[test]
fn exit_must_support_tunneled_dial() {
    let error = rejection(&format!(" front: '{SOCKS}'\n land: '{HY2}'\n"), "land");
    assert_eq!(error.code, "unsupported-group-exit-target");
}

#[test]
fn chain_member_plus_exit_is_capped_at_four_hops() {
    let hops = |front: &str| {
        format!(
            " a: '{SOCKS}'\n b: '{SS}'\n c: 'socks5://127.0.0.1:1081'\n d: 'socks5://127.0.0.1:1082'\n land: '{TROJAN}'\n front: {front}\n"
        )
    };
    admit(config(&hops("a -> b -> c"), "land")).unwrap();
    let error = rejection(&hops("a -> b -> c -> d"), "land");
    assert_eq!(error.code, "group-exit-route-too-long");
    assert_eq!(error.setting.to_string(), "groups[2].exit");
}

#[test]
fn a_final_behind_an_exit_counts_toward_the_four_hops() {
    let config = |last: &str| {
        let partial = parse_dae_config(&format!(
            "node {{\n a: '{SOCKS}'\n b: '{SS}'\n c: 'socks5://127.0.0.1:1081'\n d: 'socks5://127.0.0.1:1082'\n land: '{TROJAN}'\n long: a -> b -> {last}\n}}\ngroup {{\n proxy {{\n  filter: name(a)\n  policy: fixed(0)\n  final: long\n  exit: land\n }}\n}}\nrouting {{\n fallback: proxy\n}}\n"
        ))
        .unwrap();
        admit(partial)
    };
    config("c").unwrap();
    let error = *config("c -> d").unwrap_err().diagnostic;
    assert_eq!(error.code, "group-exit-route-too-long");
}

#[test]
fn a_hop_the_next_exit_repeats_counts_once() {
    let hops = |front: &str| {
        format!(
            " a: '{SOCKS}'\n b: '{SS}'\n c: 'socks5://127.0.0.1:1081'\n land: '{TROJAN}'\n front: {front}\n"
        )
    };
    admit(config(&hops("a -> b -> c -> land"), "land")).unwrap();
    let error = rejection(&hops("a -> b -> c -> land"), "a");
    assert_eq!(error.code, "group-exit-route-too-long");

    let nested = |inner_exit: &str| {
        let partial = parse_dae_config(&format!(
            "node {{\n a: '{SOCKS}'\n b: '{SS}'\n c: 'socks5://127.0.0.1:1081'\n land: '{TROJAN}'\n front: a -> b -> c\n}}\ngroup {{\n inner {{\n  filter: name(front)\n  policy: fixed(0)\n  exit: {inner_exit}\n }}\n proxy {{\n  filter: group(inner)\n  policy: fixed(0)\n  exit: land\n }}\n}}\nrouting {{\n fallback: proxy\n}}\n"
        ))
        .unwrap();
        admit(partial)
    };
    nested("land").unwrap();
    let error = *nested("b").unwrap_err().diagnostic;
    assert_eq!(error.code, "group-exit-route-too-long");
}
