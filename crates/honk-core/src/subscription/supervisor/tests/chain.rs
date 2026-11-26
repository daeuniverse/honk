use super::*;

#[tokio::test]
async fn startup_binds_multiple_partial_chains_after_cached_provider_restore() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let mut provider = authorized(uuid::Uuid::new_v4(), 1, "http://unused.test/feed".into());
    provider.subscription.download_detour = "routing".into();
    const BODY: &str = "socks5://127.0.0.1:1081#land";
    store
        .store_content(&provider.subscription, BODY.into())
        .await
        .unwrap();
    let mut config = honk_config::parser::parse_dae_config(
        "node {\n via: front -> land\n reverse: land -> front\n front: 'socks5://127.0.0.1:1080'\n}\n group { pool { filter: name(via) } }",
    )
    .unwrap();
    config.subscriptions.push(provider.subscription.clone());
    // An old structured alias cannot claim a physical ID before startup binding.
    config.nodes[0].id = parsed(&provider.subscription, BODY)[0].id;
    config.validate_detailed().unwrap();
    assert!(config.groups[0].nodes.is_empty());
    let mut state =
        SupervisorState::new(Arc::new(SubscriptionManager::new().unwrap()), Some(store));
    state.reconcile(vec![provider.clone()]);
    state.prepare_startup(&mut config, Vec::new()).await;
    assert!(
        state.observations.read()[&provider.subscription.id]
            .load
            .cached
    );

    let config = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();
    assert_eq!(node_names(&config), ["via", "reverse", "front", "land"]);
    let [via, reverse, front, land] = config.nodes.as_slice() else {
        panic!("unexpected assembled nodes");
    };
    assert_eq!(land.subscription_id, Some(provider.subscription.id));
    assert_eq!(via.resolved_chain_hops().unwrap(), [front.id, land.id]);
    assert_eq!(reverse.resolved_chain_hops().unwrap(), [land.id, front.id]);
    assert_ne!(via.id, reverse.id);
    assert_eq!(config.groups[0].nodes, [via.id]);
    state.shutdown().await.unwrap();
}
