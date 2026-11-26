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

#[tokio::test]
async fn cross_provider_dedup_cascades_dropped_or_ambiguous_hops_and_prunes_orphans() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut first = authorized(uuid::Uuid::new_v4(), 1, format!("{url}/first"));
    first.subscription.name = "first".into();
    let mut second = authorized(uuid::Uuid::new_v4(), 1, format!("{url}/second"));
    second.subscription.name = "second".into();

    let first_body = r#"proxies:
  - {name: shared-front, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: dup-chain, type: socks5, server: 127.0.0.1, port: 1081, dialer-proxy: shared-front}
  - {name: ambig-name, type: socks5, server: 127.0.0.1, port: 1099}
"#;
    let second_body = r#"proxies:
  - {name: own-front, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: dropped-chain, type: socks5, server: 127.0.0.1, port: 1082, dialer-proxy: own-front}
  - {name: dup-front-2, type: socks5, server: 127.0.0.1, port: 1083}
  - {name: surviving-chain, type: socks5, server: 127.0.0.1, port: 1084, dialer-proxy: dup-front-2}
  - {name: ambig-name, type: socks5, server: 127.0.0.1, port: 1085}
  - {name: ambig-chain, type: socks5, server: 127.0.0.1, port: 1086, dialer-proxy: ambig-name}
"#;

    store
        .store_content(&first.subscription, first_body.into())
        .await
        .unwrap();
    store
        .store_content(&second.subscription, second_body.into())
        .await
        .unwrap();

    let mut config = Config {
        subscriptions: vec![first.subscription.clone(), second.subscription.clone()],
        ..Default::default()
    };
    let mut state =
        SupervisorState::new(Arc::new(SubscriptionManager::new().unwrap()), Some(store));
    state.reconcile(vec![first.clone(), second.clone()]);
    state.prepare_startup(&mut config, Vec::new()).await;

    let assembled = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();
    let second_names: Vec<_> = assembled
        .nodes
        .iter()
        .filter(|n| n.subscription_id == Some(second.subscription.id))
        .filter(|n| !n.name.starts_with("chain-hop-"))
        .map(|n| n.name.as_str())
        .collect();
    assert_eq!(
        second_names,
        ["dup-front-2", "surviving-chain", "ambig-name"]
    );
    let second_backing_count = assembled
        .nodes
        .iter()
        .filter(|n| n.subscription_id == Some(second.subscription.id))
        .filter(|n| n.name.starts_with("chain-hop-"))
        .count();
    assert_eq!(second_backing_count, 1);
    state.shutdown().await.unwrap();
}

#[tokio::test]
async fn startup_rejects_provider_chain_colliding_with_unbound_static_chain() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = authorized(
        uuid::Uuid::new_v4(),
        1,
        format!("http://{}", listener.local_addr().unwrap()),
    );

    let body = r#"proxies:
  - {name: sub_front, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: sub_land, type: socks5, server: 127.0.0.1, port: 1081}
  - {name: provider_via, type: socks5, server: 127.0.0.1, port: 1081, dialer-proxy: sub_front}
"#;
    store
        .store_content(&provider.subscription, body.into())
        .await
        .unwrap();

    let mut config = honk_config::parser::parse_dae_config(
        "node {\n kept: 'socks5://127.0.0.1:1090'\n static_via: sub_front -> sub_land\n}",
    )
    .unwrap();
    config.subscriptions.push(provider.subscription.clone());
    let mut state =
        SupervisorState::new(Arc::new(SubscriptionManager::new().unwrap()), Some(store));
    state.reconcile(vec![provider.clone()]);

    state.prepare_startup(&mut config, Vec::new()).await;

    assert_rejected(&state, provider.subscription.id);
    assert_eq!(node_names(&config), ["kept", "static_via"]);

    let front = Node::from_share_link("socks5://127.0.0.1:1080#a").unwrap();
    let land = Node::from_share_link("socks5://127.0.0.1:1081#b").unwrap();
    let mut published_chain = Node::chain_from_nodes("pub_via", &[&front, &land]).unwrap();
    let owner_id = uuid::Uuid::new_v4();
    published_chain.subscription_id = Some(owner_id);
    let mut incoming_dup = vec![Node::chain_from_nodes("inc_via", &[&front, &land]).unwrap()];
    super::super::drop_nodes_published_elsewhere(
        &[published_chain],
        &[],
        provider.subscription.id,
        &mut incoming_dup,
    );
    assert!(incoming_dup.is_empty());

    let inline_bound = Node::chain_from_nodes("inline_via", &[&front, &land]).unwrap();
    let mut bound_config = Config {
        nodes: vec![inline_bound],
        subscriptions: vec![provider.subscription.clone()],
        ..Default::default()
    };
    let store2 = SubscriptionStore::in_dir(temp.path());
    let mut state2 =
        SupervisorState::new(Arc::new(SubscriptionManager::new().unwrap()), Some(store2));
    state2.reconcile(vec![provider.clone()]);
    state2.prepare_startup(&mut bound_config, Vec::new()).await;
    assert_rejected(&state2, provider.subscription.id);
    assert_eq!(node_names(&bound_config), ["inline_via"]);
    state2.shutdown().await.unwrap();
    state.shutdown().await.unwrap();
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<parking_lot::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_logs<T>(run: impl FnOnce() -> T) -> (T, String) {
    let buffer = LogBuffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let value = tracing::subscriber::with_default(subscriber, run);
    let text = String::from_utf8(buffer.0.lock().clone()).unwrap();
    (value, text)
}

#[tokio::test]
async fn reverse_chain_hop_name_protection_and_inline_owner_diagnostics_hold() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut first = authorized(uuid::Uuid::new_v4(), 1, format!("{url}/first"));
    first.subscription.name = "first".into();
    let mut second = authorized(uuid::Uuid::new_v4(), 1, format!("{url}/second"));
    second.subscription.name = "second".into();

    let first_body = r#"proxies:
  - {name: hk, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: via-hk, type: socks5, server: 127.0.0.1, port: 1081, dialer-proxy: hk}
  - {name: static-land, type: socks5, server: 127.0.0.1, port: 1082}
"#;
    let second_body = r#"proxies:
  - {name: hk, type: socks5, server: 127.0.0.1, port: 2080}
  - {name: second-via-hk, type: socks5, server: 127.0.0.1, port: 2081, dialer-proxy: hk}
  - {name: static-front, type: socks5, server: 127.0.0.1, port: 2082}
  - {name: static-land, type: socks5, server: 127.0.0.1, port: 2083}
  - {name: inline-only, type: socks5, server: 127.0.0.1, port: 2084}
  - {name: via-inline-only, type: socks5, server: 127.0.0.1, port: 2085, dialer-proxy: inline-only}
  - {name: survivor, type: socks5, server: 127.0.0.1, port: 2086}
"#;

    store
        .store_content(&first.subscription, first_body.into())
        .await
        .unwrap();
    store
        .store_content(&second.subscription, second_body.into())
        .await
        .unwrap();

    let mut config = honk_config::parser::parse_dae_config(
        "node {\n static-front: 'socks5://127.0.0.1:1090'\n inline-only: 'socks5://127.0.0.1:1091'\n static-via: 'static-front' -> 'static-land'\n}",
    )
    .unwrap();
    config.subscriptions = vec![first.subscription.clone(), second.subscription.clone()];
    let mut state =
        SupervisorState::new(Arc::new(SubscriptionManager::new().unwrap()), Some(store));
    state.reconcile(vec![first.clone(), second.clone()]);
    state.prepare_startup(&mut config, Vec::new()).await;

    let assembled = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();
    let second_surviving: Vec<_> = assembled
        .nodes
        .iter()
        .filter(|n| n.subscription_id == Some(second.subscription.id))
        .map(|n| n.name.as_str())
        .collect();
    assert_eq!(second_surviving, ["inline-only", "survivor"]);
    state.shutdown().await.unwrap();

    let inline_hk = {
        let mut node = Node::from_share_link("socks5://127.0.0.1:1080#hk").unwrap();
        node.subscription_id = None;
        node
    };
    let mut sub_nodes = parsed(
        &second.subscription,
        "proxies:\n  - {name: hk, type: socks5, server: 127.0.0.1, port: 2080}\n  - {name: sub-chain, type: socks5, server: 127.0.0.1, port: 2081, dialer-proxy: hk}\n",
    );
    let (_, inline_log) = capture_logs(|| {
        super::super::drop_nodes_published_elsewhere(
            std::slice::from_ref(&inline_hk),
            std::slice::from_ref(&second.subscription),
            second.subscription.id,
            &mut sub_nodes,
        );
    });
    assert_eq!(
        sub_nodes
            .iter()
            .map(|n| n.name.as_str())
            .collect::<Vec<_>>(),
        ["hk"]
    );
    assert!(inline_log.contains("owners=inline"), "{inline_log}");
    assert!(!inline_log.contains("owners=\"\""), "{inline_log}");

    let inline_exit = {
        let mut node = Node::from_share_link("socks5://127.0.0.1:1081#exit").unwrap();
        node.subscription_id = None;
        node
    };
    let inline_chain = Node::chain_from_nodes("inline-via", &[&inline_hk, &inline_exit]).unwrap();
    let mut colliding_inline_id = parsed(
        &second.subscription,
        "proxies:\n  - {name: hk, type: socks5, server: 127.0.0.1, port: 1080}\n",
    );
    super::super::drop_nodes_published_elsewhere(
        &[inline_hk, inline_exit, inline_chain],
        std::slice::from_ref(&second.subscription),
        second.subscription.id,
        &mut colliding_inline_id,
    );
    assert_eq!(colliding_inline_id.len(), 1);
}
