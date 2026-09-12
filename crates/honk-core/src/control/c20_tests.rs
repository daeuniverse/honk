use super::*;
use crate::control::drain::DrainTracker;
use crate::ebpf::mock::MockEbpfBackend;
use crate::subscription::{SubscriptionSupervisor, parse_subscription_content};
use honk_config::node::{Group, Node, OutboundConfig};
use honk_config::types::NodeProtocol;
use honk_config::{Config, subscription::Subscription};
use std::sync::Arc;

const C20_DIRECT_PROVIDER_BODY: &str = include_str!("../../tests/fixtures/c20-direct-provider.txt");

pub(super) fn canonical_socks5(
    name: &str,
    address: &str,
    port: u16,
    subscription_id: Option<uuid::Uuid>,
) -> Node {
    let mut node = Node {
        name: name.to_owned(),
        address: address.to_owned(),
        port,
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        subscription_id,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn config_with_provider_node(
    node: Node,
    subscription: Option<Subscription>,
    groups: Vec<Group>,
) -> Config {
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.nodes = vec![node];
    config.subscriptions = subscription.into_iter().collect();
    config.groups = groups;
    config
}

pub(super) async fn control_plane(config: Config) -> ControlPlane {
    ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        Router::new(&[], "direct").expect("test router"),
        Arc::new(ProxyRegistry::default_resolver().expect("test proxy registry")),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).expect("test DNS resolver"),
        super::reload_tests::test_dns_forwarder(),
    )
    .expect("test control plane")
}

async fn assert_public_merge_rejected(
    config: Config,
    subscription_id: uuid::Uuid,
    nodes: Vec<Node>,
    case: &str,
) {
    let before = config.clone();
    let cp = control_plane(config).await;
    cp.merge_subscription_nodes(subscription_id, nodes, Vec::new())
        .await;
    assert_eq!(
        cp.config_handle().read().await.as_ref(),
        &before,
        "{case} must preserve the active assembled configuration"
    );
}

fn provider_config(subscription_id: uuid::Uuid) -> (Config, Node) {
    let node = canonical_socks5("provider", "192.0.2.10", 1080, Some(subscription_id));
    let inner = Group {
        name: "inner".into(),
        nodes: vec![node.id],
        ..Default::default()
    };
    let outer = Group {
        name: "outer".into(),
        nodes: vec![node.id],
        groups: vec!["inner".into()],
        ..Default::default()
    };
    let subscription = Subscription {
        id: subscription_id,
        name: "provider".into(),
        url: "https://example.test/feed".into(),
        ..Default::default()
    };
    (
        config_with_provider_node(node.clone(), Some(subscription), vec![inner, outer]),
        node,
    )
}

#[tokio::test]
async fn c20_public_merge_rejects_stale_id_before_noop_and_preserves_membership() {
    let subscription_id = uuid::Uuid::new_v4();
    let (config, canonical) = provider_config(subscription_id);
    let before = config.clone();
    let cp = control_plane(config).await;

    cp.merge_subscription_nodes(subscription_id, vec![canonical.clone()], Vec::new())
        .await;
    assert_eq!(
        cp.config_handle().read().await.as_ref(),
        &before,
        "canonical refresh remains a no-op"
    );

    let mut stale = canonical;
    stale.address = "192.0.2.11".into();
    cp.merge_subscription_nodes(subscription_id, vec![stale], Vec::new())
        .await;

    assert_eq!(
        cp.config_handle().read().await.as_ref(),
        &before,
        "stale endpoint IDs must be rejected before replacing nodes or memberships"
    );
}

#[tokio::test]
async fn c20_public_merge_rejects_two_ids_for_one_endpoint() {
    let subscription_id = uuid::Uuid::new_v4();
    let (config, canonical) = provider_config(subscription_id);
    let before = config.clone();
    let cp = control_plane(config).await;

    let mut conflicting = canonical.clone();
    conflicting.name = "second-id".into();
    conflicting.id = uuid::Uuid::new_v4();
    cp.merge_subscription_nodes(subscription_id, vec![canonical, conflicting], Vec::new())
        .await;

    assert_eq!(
        cp.config_handle().read().await.as_ref(),
        &before,
        "one endpoint cannot be admitted under two supplied IDs"
    );
}

#[tokio::test]
async fn c20_public_merge_rejects_nil_duplicate_and_cross_source_ids() {
    let subscription_id = uuid::Uuid::new_v4();
    let (config, canonical) = provider_config(subscription_id);

    let mut nil = canonical.clone();
    nil.id = uuid::Uuid::nil();
    assert_public_merge_rejected(config.clone(), subscription_id, vec![nil], "nil ID").await;

    assert_public_merge_rejected(
        config.clone(),
        subscription_id,
        vec![canonical.clone(), canonical.clone()],
        "same-name duplicate",
    )
    .await;

    let static_node = canonical_socks5("static", "192.0.2.12", 1080, None);
    let provider = canonical_socks5("provider", "192.0.2.13", 1080, Some(subscription_id));
    let mut cross_source = static_node.clone();
    cross_source.name = "provider-replacement".into();
    cross_source.subscription_id = Some(subscription_id);
    let mut cross_config =
        config_with_provider_node(provider, Some(config.subscriptions[0].clone()), Vec::new());
    cross_config.nodes.insert(0, static_node);
    assert_public_merge_rejected(
        cross_config,
        subscription_id,
        vec![cross_source],
        "cross-source duplicate",
    )
    .await;
}

#[tokio::test]
async fn c20_public_merge_rebuilds_filters_and_prunes_removed_direct_ids() {
    let subscription_id = uuid::Uuid::new_v4();
    let (mut config, old) = provider_config(subscription_id);
    let keeper = canonical_socks5("keeper", "192.0.2.50", 1080, None);
    config.nodes.push(keeper.clone());
    config.groups[0].nodes.push(keeper.id);
    config.groups[1].nodes.push(keeper.id);
    config.groups.push(Group {
        name: "filtered".into(),
        filters: vec!["subtag('provider')".into()],
        ..Default::default()
    });
    honk_config::parser::resolve_group_filters(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
    );
    let cp = control_plane(config).await;

    let replacement = canonical_socks5("provider-new", "192.0.2.11", 1080, Some(subscription_id));
    cp.merge_subscription_nodes(subscription_id, vec![replacement.clone()], Vec::new())
        .await;

    let config_handle = cp.config_handle();
    let after = config_handle.read().await;
    assert!(!after.nodes.iter().any(|node| node.id == old.id));
    assert!(after.nodes.iter().any(|node| node.id == replacement.id));
    assert!(after.groups[1].nodes.contains(&keeper.id));
    assert!(!after.groups[1].nodes.contains(&old.id));
    assert_eq!(after.groups[1].groups, vec!["inner".to_string()]);
    assert_eq!(after.groups[2].nodes, vec![replacement.id]);
}
#[tokio::test]
async fn c20_public_merge_sets_missing_provider_provenance() {
    let subscription_id = uuid::Uuid::new_v4();
    let (config, mut candidate) = provider_config(subscription_id);
    candidate.subscription_id = None;
    let before = config.clone();
    let cp = control_plane(config).await;

    cp.merge_subscription_nodes(subscription_id, vec![candidate], Vec::new())
        .await;

    assert_eq!(
        cp.config_handle().read().await.as_ref(),
        &before,
        "missing provenance is filled from the requested provider before equality"
    );
}

#[tokio::test]
async fn c20_authorized_refresh_rejects_conflicting_provider_before_noop() {
    let subscription_id = uuid::Uuid::new_v4();
    let (config, canonical) = provider_config(subscription_id);
    let before = config.clone();
    let cp = control_plane(config).await;
    let authorizations =
        crate::subscription::SubscriptionAuthorizations::new(&before.subscriptions)
            .expect("valid provider authorization");
    let revision = authorizations
        .revision(subscription_id)
        .expect("provider revision");

    let mut conflicting = canonical;
    conflicting.subscription_id = Some(uuid::Uuid::new_v4());
    assert!(
        cp.merge_authorized_subscription_nodes_with_drain(
            subscription_id,
            revision,
            &authorizations,
            vec![conflicting],
            Vec::new(),
            &DrainTracker::new(),
        )
        .await
        .is_err()
    );
    assert_eq!(
        cp.config_handle().read().await.as_ref(),
        &before,
        "an authorized refresh from another provider must preserve the active generation"
    );
}

#[tokio::test]
async fn c20_authorized_refresh_admits_reserved_provider_name() {
    let subscription_id = uuid::Uuid::new_v4();
    let subscription = Subscription {
        id: subscription_id,
        name: "provider".into(),
        url: "https://example.test/feed".into(),
        ..Default::default()
    };
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.ensure_builtin_nodes();
    config.subscriptions.push(subscription.clone());
    let cp = control_plane(config).await;
    let authorizations =
        crate::subscription::SubscriptionAuthorizations::new(std::slice::from_ref(&subscription))
            .expect("valid provider authorization");
    let revision = authorizations
        .revision(subscription_id)
        .expect("provider revision");
    let nodes =
        parse_subscription_content(&subscription, C20_DIRECT_PROVIDER_BODY).expect("provider body");

    assert!(
        cp.merge_authorized_subscription_nodes_with_drain(
            subscription_id,
            revision,
            &authorizations,
            nodes,
            Vec::new(),
            &DrainTracker::new(),
        )
        .await
        .unwrap()
    );
    let handle = cp.config_handle();
    let after = handle.read().await;
    let provider = after
        .nodes
        .iter()
        .find(|node| node.subscription_id == Some(subscription_id))
        .expect("provider node admitted");
    assert_eq!(provider.name, "direct");
    assert_eq!(provider.id, provider.derive_id());
}

#[tokio::test]
async fn c20_public_reload_rejects_stale_config_before_side_effects() {
    let canonical = canonical_socks5("static", "192.0.2.20", 1080, None);
    let config = config_with_provider_node(canonical.clone(), None, Vec::new());
    let cp = control_plane(config.clone()).await;

    let mut stale = config.clone();
    stale.nodes[0].address = "192.0.2.21".into();
    assert!(!cp.reload_runtime_config(stale, Default::default()).await);
    assert_eq!(
        cp.config_handle().read().await.as_ref(),
        &config,
        "a public reload rejection preserves the old Config"
    );
}

#[tokio::test]
async fn c20_startup_post_prepare_rejects_stale_node_identity() {
    let canonical = canonical_socks5("startup", "192.0.2.30", 1080, None);
    let mut config = config_with_provider_node(canonical, None, Vec::new());
    config.nodes[0].address = "192.0.2.31".into();

    let _supervisor = SubscriptionSupervisor::prepare(&mut config, None, Vec::new())
        .await
        .expect("post-prepare fixture");
    honk_config::parser::resolve_group_filters(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
    );

    let result = ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        Router::new(&[], "direct").expect("test router"),
        Arc::new(ProxyRegistry::default_resolver().expect("test proxy registry")),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).expect("test DNS resolver"),
        super::reload_tests::test_dns_forwarder(),
    );
    assert!(
        result.is_err(),
        "startup must reject stale IDs after subscription preparation"
    );
}

#[tokio::test]
async fn c20_startup_post_prepare_admits_reserved_provider_name() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let subscription = Subscription {
        name: "provider".into(),
        url: format!("http://{}/subscription", listener.local_addr().unwrap()),
        ..Default::default()
    };
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        while stream.read_line(&mut line).await.unwrap() != 0 {
            if line == "\r\n" {
                break;
            }
            line.clear();
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    C20_DIRECT_PROVIDER_BODY.len(),
                    C20_DIRECT_PROVIDER_BODY,
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let subscription_id = subscription.id;
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.ensure_builtin_nodes();
    config.subscriptions.push(subscription);
    let _supervisor = SubscriptionSupervisor::prepare(&mut config, None, Vec::new())
        .await
        .expect("startup subscription preparation");
    server.await.unwrap();
    let cp = control_plane(config).await;
    let handle = cp.config_handle();
    let after = handle.read().await;
    let provider = after
        .nodes
        .iter()
        .find(|node| node.subscription_id == Some(subscription_id))
        .expect("provider node admitted");
    assert_eq!(provider.name, "direct");
}
