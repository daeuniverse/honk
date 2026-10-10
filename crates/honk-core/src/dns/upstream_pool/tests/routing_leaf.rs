use honk_config::group::GroupPolicy;
use honk_outbound::group::GroupManager;

use super::*;

#[tokio::test]
async fn resolve_dial_route_node_by_name() {
    let node = test_node("hk-1");
    let upstreams = [
        DnsUpstream {
            outbound: Some("hk-1".into()),
            ..make_upstream("node", "192.0.2.53:53", DnsProtocol::Tcp)
        },
        DnsUpstream {
            outbound: Some("direct".into()),
            ..make_upstream("direct", "192.0.2.53:53", DnsProtocol::Tcp)
        },
        DnsUpstream {
            outbound: Some("missing".into()),
            ..make_upstream("missing", "192.0.2.53:53", DnsProtocol::Tcp)
        },
    ];
    let pool =
        UpstreamPool::new_with_proxy(&upstreams, make_router(), None, vec![node.clone()], vec![])
            .unwrap();

    let route = pool
        .resolve_dial_route(&pool.entries["node"])
        .await
        .unwrap();
    assert_eq!(route.node.unwrap().name, "hk-1");
    assert!(
        pool.resolve_dial_route(&pool.entries["direct"])
            .await
            .unwrap()
            .node
            .is_none()
    );
    assert!(
        pool.resolve_dial_route(&pool.entries["missing"])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn resolve_dial_route_group_uses_group_manager_selector() {
    let alpha = test_node("alpha");
    let beta = test_node("beta");
    let mut group = test_group("proxy", GroupPolicy::Selector, vec![alpha.id, beta.id]);
    group.default = Some("beta".into());
    let group_manager = GroupManager::new(&[group], &[alpha.clone(), beta.clone()]).into_shared();
    group_manager
        .read()
        .set_selector_choice(
            "proxy",
            "alpha",
            honk_outbound::group::SelectorNetworks::Both,
        )
        .unwrap();
    let upstream = DnsUpstream {
        outbound: Some("proxy".into()),
        ..make_upstream("google", "192.0.2.53:53", DnsProtocol::Https)
    };
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![alpha, beta], vec![])
            .unwrap()
            .with_group_manager(group_manager);

    assert_eq!(
        pool.resolve_dial_route(&pool.entries["google"])
            .await
            .unwrap()
            .node
            .unwrap()
            .name,
        "alpha"
    );
    pool.group_manager
        .read()
        .as_ref()
        .unwrap()
        .read()
        .set_selector_choice(
            "proxy",
            "beta",
            honk_outbound::group::SelectorNetworks::Both,
        )
        .unwrap();
    assert_eq!(
        pool.resolve_dial_route(&pool.entries["google"])
            .await
            .unwrap()
            .node
            .unwrap()
            .name,
        "beta"
    );
}

#[tokio::test]
async fn resolve_dial_route_group_without_gm_uses_first_member() {
    let first = test_node("first");
    let second = test_node("second");
    let group = test_group("proxy", GroupPolicy::URLTest, vec![first.id, second.id]);
    let upstream = DnsUpstream {
        outbound: Some("proxy".into()),
        ..make_upstream("google", "192.0.2.53:53", DnsProtocol::Tcp)
    };
    let pool = UpstreamPool::new_with_proxy(
        &[upstream],
        make_router(),
        None,
        vec![first, second],
        vec![group],
    )
    .unwrap();
    assert_eq!(
        pool.resolve_dial_route(&pool.entries["google"])
            .await
            .unwrap()
            .node
            .unwrap()
            .name,
        "first"
    );
}
