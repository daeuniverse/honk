//! Parse the repository-root example `.dae` configuration files to keep them
//! in sync with the `Config` schema and the dae-syntax parser.

use honk_config::Config;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn load(name: &str) -> Config {
    let path = repo_root().join(name);
    Config::from_file(path.to_str().unwrap())
        .unwrap_or_else(|e| panic!("{name} failed to parse: {e}"))
}

#[test]
fn test_config_dae_parses() {
    let config = load("config.dae");
    config.validate().expect("config.dae invalid");

    assert_eq!(config.global.lan_interface, vec!["podman0".to_string()]);
    assert!(config.global.auto_config_kernel_parameter);

    // One socks5 share-link node plus at least one group. (config.dae is a
    // live example: assert shape, not exact rule counts.)
    assert_eq!(config.nodes.len(), 1);
    assert_eq!(config.nodes[0].name, "iris-1");
    assert!(!config.groups.is_empty());
    assert_eq!(config.groups[0].name, "iris");

    // Routing ends in a direct fallback.
    assert!(!config.routing.rules.is_empty());
    assert_eq!(config.routing.default_outbound, "direct");

    // DNS section with local and remote upstreams.
    assert_eq!(config.dns.upstream.len(), 2);

    // Experimental sections parsed from dae syntax.
    assert_eq!(
        config.experimental.clash_api.external_controller,
        "0.0.0.0:9090"
    );
    assert!(config.experimental.cache_file.enabled);
}

#[test]
fn test_config_min_dae_parses() {
    let config = load("config.min.dae");
    config.validate().expect("config.min.dae invalid");

    assert_eq!(config.global.lan_interface, vec!["veth0".to_string()]);
    assert_eq!(config.nodes.len(), 1);
    assert_eq!(config.nodes[0].name, "iris-1");
    assert_eq!(config.groups.len(), 1);
    assert_eq!(config.groups[0].name, "iris");
    assert_eq!(config.routing.rules.len(), 1);
    assert_eq!(config.routing.default_outbound, "direct");
}

#[test]
fn test_example_dae_parses() {
    let config = load("example.dae");
    config.validate().expect("example.dae invalid");

    // Four share-link nodes and two groups (manual + auto).
    assert_eq!(config.nodes.len(), 4);
    assert_eq!(config.groups.len(), 2);
    assert_eq!(config.groups[0].name, "manual");
    assert_eq!(config.groups[1].name, "auto");

    // Seven routing rules, falling back to the manual group.
    assert_eq!(config.routing.rules.len(), 7);
    assert_eq!(config.routing.default_outbound, "manual");

    // Two DNS upstreams; clash API on localhost; cache file enabled in sample.
    assert_eq!(config.dns.upstream.len(), 2);
    assert_eq!(
        config.experimental.clash_api.external_controller,
        "127.0.0.1:9090"
    );
    assert!(config.experimental.cache_file.enabled);
    assert_eq!(config.experimental.cache_file.path, "cache.db");
}
