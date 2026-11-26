use super::*;
use honk_config::config::BLOCK_NODE_ID;
fn named_node<'a>(config: &'a Config, name: &str) -> &'a Node {
    config.nodes.iter().find(|node| node.name == name).unwrap()
}

fn selected_tcp_v4(cp: &ControlPlane, group: &str) -> uuid::Uuid {
    cp.group_manager
        .read()
        .select_nodes_in_order_for_domain(group, ProbeDomain::Tcp, IpVersion::V4)[0]
        .id
}

fn explicit_block_config() -> Config {
    let mut config = honk_config::parser::parse_dae_config(
        "global { nfqueue_enable: false }
         node {
             front: 'socks5://127.0.0.1:1080'
             land: 'socks5://127.0.0.1:1081'
         }",
    )
    .unwrap();
    config.ensure_builtin_nodes();
    config.groups.push(Group {
        name: "quarantine".into(),
        final_outbound: Some("block".into()),
        ..Default::default()
    });
    config
}

#[tokio::test]
async fn programmatic_startup_with_unrelated_chain_keeps_empty_group_blocking() {
    let mut config = explicit_block_config();
    config
        .nodes
        .push(Node::chain("via", vec!["front".into(), "land".into()]));
    let cp = crate::control::tests::support::control_plane(config);
    let active = cp.config.read().await;
    assert_eq!(selected_tcp_v4(&cp, "quarantine"), BLOCK_NODE_ID);
    assert!(active.groups[0].nodes.is_empty());
    assert!(named_node(&active, "via").resolved_chain_hops().is_some());
}

#[tokio::test]
async fn public_reload_with_unrelated_chain_keeps_empty_group_blocking() {
    let mut config = explicit_block_config();
    let cp = crate::control::tests::support::control_plane(config.clone());
    assert_eq!(selected_tcp_v4(&cp, "quarantine"), BLOCK_NODE_ID);

    config
        .nodes
        .push(Node::chain("via", vec!["front".into(), "land".into()]));
    assert!(cp.reload_runtime_config(config, Default::default()).await);
    let active = cp.config.read().await;
    assert_eq!(selected_tcp_v4(&cp, "quarantine"), BLOCK_NODE_ID);
    assert!(active.groups[0].nodes.is_empty());
    assert!(named_node(&active, "via").resolved_chain_hops().is_some());
}

#[tokio::test]
async fn parsed_dae_implicit_group_keeps_all_eligible_nodes_after_chain_binding() {
    let mut parsed = honk_config::parser::parse_dae_config(
        "global { nfqueue_enable: false }
         node {
             front: 'socks5://127.0.0.1:1080'
             land: 'socks5://127.0.0.1:1081'
             via: front -> land
         }
         group { pool {
             policy: fallback
             final: block
         } }",
    )
    .unwrap();
    assert!(parsed.groups[0].nodes.is_empty());
    parsed.ensure_builtin_nodes();
    let cp = crate::control::tests::support::control_plane(parsed);
    let initial = cp.config.read().await.clone();
    let expected = ["front", "land", "via"].map(|name| named_node(&initial, name).id);
    assert_eq!(initial.groups[0].nodes, expected);
    assert_eq!(selected_tcp_v4(&cp, "pool"), expected[0]);

    let mut candidate = initial.as_ref().clone();
    let spare = Node::from_share_link("socks5://127.0.0.1:1082#spare").unwrap();
    let spare_id = spare.id;
    candidate.nodes.push(spare);
    assert!(
        cp.reload_runtime_config(candidate, Default::default())
            .await
    );
    let active = cp.config.read().await;
    assert_eq!(
        active.groups[0].nodes,
        [expected[0], expected[1], expected[2], spare_id]
    );
    assert_eq!(selected_tcp_v4(&cp, "pool"), expected[0]);
}

#[tokio::test]
async fn provider_refresh_keeps_legacy_membership_only_between_chain_free_snapshots() {
    use crate::control::tests::support::{canonical_socks5, control_plane};

    let mut config = honk_config::parser::parse_dae_config(
        "global { nfqueue_enable: false }\ngroup { source { policy: select } }",
    )
    .unwrap();
    config.ensure_builtin_nodes();
    config.groups.push(Group {
        name: "explicit".into(),
        final_outbound: Some("block".into()),
        ..Default::default()
    });
    let cp = control_plane(config);
    let provider = uuid::Uuid::new_v4();
    let physical =
        |name, port| canonical_socks5(name, &format!("127.0.0.1:{port}"), port, Some(provider));
    for (nodes, explicit, source) in [
        (vec![physical("old", 1080)], &["old"][..], &["old"][..]),
        (
            vec![
                physical("front", 1081),
                physical("land", 1082),
                Node::chain("via", vec!["front".into(), "land".into()]),
            ],
            &[][..],
            &["front", "land", "via"][..],
        ),
        (vec![physical("next", 1083)], &[][..], &["next"][..]),
        (vec![physical("last", 1084)], &["last"][..], &["last"][..]),
    ] {
        cp.merge_subscription_nodes(provider, nodes, Vec::new())
            .await;
        let active = cp.config.read().await;
        for (group, names) in [("explicit", explicit), ("source", source)] {
            let expected: Vec<_> = names
                .iter()
                .map(|name| named_node(&active, name).id)
                .collect();
            let actual = active.groups.iter().find(|g| g.name == group).unwrap();
            assert_eq!(actual.nodes, expected, "{group}: {names:?}");
            assert_eq!(
                selected_tcp_v4(&cp, group),
                expected.first().copied().unwrap_or(BLOCK_NODE_ID)
            );
        }
    }
}

#[tokio::test]
async fn provider_refresh_keeps_explicit_empty_group_with_exit_blocking() {
    let mut config = explicit_block_config();
    config.groups[0].exit = Some("land".into());
    let cp = crate::control::tests::support::control_plane(config);
    assert_eq!(selected_tcp_v4(&cp, "quarantine"), BLOCK_NODE_ID);

    let provider = uuid::Uuid::new_v4();
    let supplied = Node::from_share_link("socks5://127.0.0.1:1082#supplied").unwrap();
    let supplied_id = supplied.id;
    cp.merge_subscription_nodes(provider, vec![supplied], Vec::new())
        .await;

    let active = cp.config.read().await;
    assert_eq!(named_node(&active, "supplied").id, supplied_id);
    assert!(active.groups[0].nodes.is_empty());
    assert_eq!(selected_tcp_v4(&cp, "quarantine"), BLOCK_NODE_ID);
}

#[tokio::test]
async fn chain_reload_preserves_health_on_rename_and_dials_the_replacement() -> anyhow::Result<()> {
    use crate::control::tests::support::control_plane;
    use crate::test_support::socks5_relay;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let front = socks5_relay().await;
    let land = socks5_relay().await;
    let replacement = socks5_relay().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let deadline = Duration::from_secs(5);
    let candidate = |entry: &str, exit| {
        honk_config::parser::parse_dae_config(&format!(
            "global {{ nfqueue_enable: false }}\nnode {{\n via: {entry} -> land\n {entry}: 'socks5://{}'\n land: 'socks5://{exit}'\n}}\ngroup {{ pool {{ filter: name(via) }} }}",
            front.addr,
        ))
        .unwrap()
    };

    let cp = control_plane(candidate("front", land.addr));
    let initial = cp.config.read().await.clone();
    let id = named_node(&initial, "via").id;
    let front_id = named_node(&initial, "front").id;
    let land_id = named_node(&initial, "land").id;
    assert_eq!(initial.groups[0].nodes, [id]);
    let old_generation = cp.runtime_registry.read().clone();
    let mut old = cp
        .proxy_registry
        .dial_runtime(Arc::clone(&old_generation), id, target, None, deadline)
        .await?;
    let (mut old_peer, _) = tokio::time::timeout(deadline, listener.accept()).await??;

    cp.alive_set
        .report_unavailable_forced(id, ProbeDomain::Tcp, IpVersion::V4);
    assert!(
        !cp.alive_set
            .is_alive_for(id, ProbeDomain::Tcp, IpVersion::V4)
    );
    assert!(
        cp.reload_runtime_config(candidate("renamed", land.addr), Default::default())
            .await
    );
    let renamed = cp.config.read().await.clone();
    assert_eq!(named_node(&renamed, "renamed").id, front_id);
    assert_eq!(named_node(&renamed, "via").id, id);
    assert_eq!(
        named_node(&renamed, "via").resolved_chain_hops().unwrap(),
        [front_id, land_id]
    );
    assert_eq!(renamed.groups[0].nodes, [id]);
    assert!(
        !cp.alive_set
            .is_alive_for(id, ProbeDomain::Tcp, IpVersion::V4)
    );

    // A programmatic caller can start with last generation's bound chain and
    // explicit member UUID, then replace only the physical node definition.
    let mut changed = renamed.as_ref().clone();
    changed.groups[0].filters.clear();
    let new_land = named_node(&candidate("renamed", replacement.addr), "land").clone();
    let new_land_id = new_land.id;
    let land_index = changed
        .nodes
        .iter()
        .position(|node| node.name == "land")
        .unwrap();
    changed.nodes[land_index] = new_land;
    assert!(cp.reload_runtime_config(changed, Default::default()).await);

    let current = cp.config.read().await.clone();
    let via = named_node(&current, "via");
    assert_ne!(via.id, id);
    assert_ne!(new_land_id, land_id);
    assert_eq!(via.resolved_chain_hops().unwrap(), [front_id, new_land_id]);
    assert_eq!(current.groups[0].nodes, [via.id]);
    let registrations = cp.alive_set.registered_nodes();
    assert!(!registrations.contains_key(&id));
    assert!(registrations.contains_key(&via.id));
    assert!(
        cp.alive_set
            .is_alive_for(via.id, ProbeDomain::Tcp, IpVersion::V4)
    );

    let selected = cp
        .group_manager
        .read()
        .select_nodes_in_order_for_domain("pool", ProbeDomain::Tcp, IpVersion::V4)
        .first()
        .unwrap()
        .id;
    let generation = cp.runtime_registry.read().clone();
    assert_eq!(selected, via.id);
    assert!(generation.get(&id).is_none());
    let mut new = cp
        .proxy_registry
        .dial_runtime(generation, selected, target, None, deadline)
        .await?;
    let (mut new_peer, _) = tokio::time::timeout(deadline, listener.accept()).await??;

    tokio::time::timeout(deadline, async {
        old.stream.write_all(b"old").await?;
        new.stream.write_all(b"new").await?;
        let mut bytes = [0; 3];
        old_peer.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"old");
        new_peer.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"new");
        Ok::<_, std::io::Error>(())
    })
    .await??;
    assert_eq!(*front.requests.lock(), [land.addr, replacement.addr]);
    assert_eq!(*land.requests.lock(), [target]);
    assert_eq!(*replacement.requests.lock(), [target]);
    Ok(())
}

#[tokio::test]
async fn provider_chain_indexes_only_physical_hostnames_for_subtag() {
    let config = honk_config::parser::parse_dae_config(
        "global { nfqueue_enable: false }\nsubscription {\n P: 'https://sub.invalid/'\n}\n\
         dns {\n upstream {\n  via: 'udp://192.0.2.53:53' -> direct\n }\n\
         routing {\n  request {\n   subtag(P) -> via\n   fallback: via\n  }\n }\n}",
    )
    .unwrap();
    let provider = config.subscriptions[0].id;
    let auth = crate::subscription::SubscriptionAuthorizations::new(&config.subscriptions).unwrap();
    let revision = auth.revision(provider).unwrap();
    let cp = crate::control::tests::support::control_plane(config);
    let front = Node::from_share_link("socks5://front.example:1080#front").unwrap();
    let exit = Node::from_share_link("socks5://192.0.2.1:1081#exit").unwrap();
    let hop_ids = [front.id, exit.id];
    let nodes = vec![
        front,
        exit,
        Node::chain("via", vec!["front".into(), "exit".into()]),
    ];
    let outcome = cp
        .merge_authorized_subscription_nodes_with_drain(
            provider,
            revision,
            &auth,
            nodes,
            Vec::new(),
            &DrainTracker::new(),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, ReloadOutcome::Committed { .. }));
    let mut merged = cp.config.read().await.as_ref().clone();
    assert_eq!(
        named_node(&merged, "via").resolved_chain_hops().unwrap(),
        hop_ids
    );
    assert_eq!(
        crate::dns::node_host::index(&merged),
        std::collections::HashMap::from([("front.example".to_owned(), vec!["P".to_owned()])]),
    );
    merged.dns.routing.request.rules.clear();
    assert!(crate::dns::node_host::index(&merged).is_empty());
}

#[tokio::test]
async fn chain_provider_refresh_rebinds_before_rebase_and_rejects_a_missing_hop() {
    use crate::control::tests::support::control_plane;
    use crate::subscription::{SubscriptionAuthorizations, parse_subscription_content};

    let sub = subscription(11, "provider", None);
    let id = sub.id;
    let provider_nodes = |url| parse_subscription_content(&sub, url).unwrap();
    let mut config = honk_config::parser::parse_dae_config(
        "global { nfqueue_enable: false }\nnode {\n via: front -> land\n front: 'socks5://127.0.0.1:1080'\n}\n group { pool { filter: name(via) } }",
    )
    .unwrap();
    config.subscriptions.push(sub.clone());
    config
        .nodes
        .extend(provider_nodes("socks5://old:secret@127.0.0.1:1081#land"));
    let legacy_id = uuid::Uuid::from_u128(510);
    config.nodes[0].id = legacy_id;
    config.groups.push(Group {
        name: "explicit".into(),
        nodes: vec![legacy_id],
        groups: vec!["pool".into()],
        ..Default::default()
    });
    let cp = control_plane(config);
    let previous = cp.config.read().await.clone();
    let old_chain_id = named_node(&previous, "via").id;
    let front_id = named_node(&previous, "front").id;
    let old_land_id = named_node(&previous, "land").id;
    cp.alive_set
        .report_unavailable_forced(old_chain_id, ProbeDomain::Tcp, IpVersion::V4);

    let mut authorizations = SubscriptionAuthorizations::new(&previous.subscriptions).unwrap();
    let revision = authorizations.revision(id).unwrap();
    let drain = DrainTracker::new();
    let mut replacements =
        provider_nodes("socks5://new:secret@127.0.0.1:1081#land\nsocks5://127.0.0.1:1083#mid");
    let new_land_id = replacements[0].id;
    replacements.extend([
        Node::chain("reverse", vec!["land".into(), "front".into()]),
        Node::chain(
            "extended",
            vec!["front".into(), "mid".into(), "land".into()],
        ),
    ]);
    let refreshed = cp
        .merge_authorized_subscription_nodes_with_drain(
            id,
            revision,
            &authorizations,
            replacements,
            Vec::new(),
            &drain,
        )
        .await
        .unwrap();
    assert!(matches!(refreshed, ReloadOutcome::Committed { .. }));

    let active = cp.config.read().await.clone();
    let active_chain = named_node(&active, "via");
    assert_ne!(old_land_id, new_land_id);
    assert_ne!(old_chain_id, active_chain.id);
    assert_eq!(
        active_chain.resolved_chain_hops().unwrap(),
        [front_id, new_land_id]
    );
    assert_eq!(active.groups[0].nodes, [active_chain.id]);
    assert_eq!(active.groups[1].nodes, [active_chain.id]);
    assert!(
        cp.alive_set
            .is_alive_for(active_chain.id, ProbeDomain::Tcp, IpVersion::V4)
    );
    assert!(!cp.alive_set.registered_nodes().contains_key(&old_chain_id));
    assert_eq!(
        named_node(&active, "reverse")
            .resolved_chain_hops()
            .unwrap(),
        [new_land_id, front_id]
    );
    let exit_id = active_chain.resolved_chain_hops().unwrap().last().unwrap();
    let exit = cp.runtime_registry.read().get(exit_id).unwrap();
    assert_eq!(exit.node.id, new_land_id);
    assert_eq!(exit.node.socks5().unwrap().username.as_deref(), Some("new"));

    let mut reread = previous.as_ref().clone();
    reread.nodes[0] = Node::chain("via", vec!["front".into(), "land".into()]);
    reread.nodes[0].id = old_chain_id;
    reread.subscriptions[0].id = uuid::Uuid::from_u128(12);
    let replayed = cp
        .apply_sighup_config(
            reread,
            Vec::new(),
            &drain,
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        replayed,
        ReloadOutcome::Noop {
            generation: refreshed.generation().unwrap(),
        }
    );
    assert_eq!(
        named_node(cp.config.read().await.as_ref(), "via").id,
        active_chain.id
    );

    let accepted = cp.config.read().await.clone();
    let generation = cp.runtime_registry.read().clone();
    for (body, code) in [
        (
            "socks5://127.0.0.1:1084#unrelated",
            "invalid-chain-hop-reference",
        ),
        (
            "socks5://127.0.0.1:1084#land\nsocks5://127.0.0.1:1085#land",
            "ambiguous-chain-hop-reference",
        ),
    ] {
        let rejection = cp
            .merge_authorized_subscription_nodes_with_drain(
                id,
                authorizations.revision(id).unwrap(),
                &authorizations,
                provider_nodes(body),
                Vec::new(),
                &drain,
            )
            .await
            .unwrap_err();
        assert_eq!(rejection.diagnostic.code, code);
        assert!(Arc::ptr_eq(&*cp.config.read().await, &accepted));
        assert!(Arc::ptr_eq(&cp.runtime_registry.read(), &generation));
    }
}

#[tokio::test]
async fn public_provider_refresh_dials_rebound_explicit_member() -> anyhow::Result<()> {
    use crate::control::tests::support::control_plane;
    use crate::subscription::SubscriptionAuthorizations;
    use crate::test_support::{socks5_chain, socks5_relay};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let front = socks5_relay().await;
    let old_exit = socks5_relay().await;
    let new_exit = socks5_relay().await;
    let provider = subscription(21, "provider", None);
    let provider_id = provider.id;
    let [mut via, entry, mut exit] = socks5_chain(&front, &old_exit);
    let old_id = via.id;
    let entry_id = entry.id;
    via.subscription_id = Some(provider_id);
    exit.subscription_id = Some(provider_id);
    let mut config = Config {
        subscriptions: vec![provider],
        nodes: vec![entry, exit, via],
        groups: vec![
            Group {
                name: "pool".into(),
                policy: GroupPolicy::Fallback,
                nodes: vec![old_id],
                groups: vec!["alternative".into()],
                ..Default::default()
            },
            Group {
                name: "alternative".into(),
                policy: GroupPolicy::Fallback,
                nodes: vec![entry_id],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    config.global.nfqueue_enable = false;
    let cp = control_plane(config);
    assert_eq!(selected_tcp_v4(&cp, "pool"), old_id);
    assert_eq!(selected_tcp_v4(&cp, "alternative"), entry_id);

    let history = |id| {
        cp.alive_set
            .get_probe_history(id, ProbeDomain::Tcp, IpVersion::V4)
    };
    cp.alive_set.record_probe_latency(
        old_id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(23),
    );
    assert!(!history(old_id).is_empty());
    cp.alive_set
        .report_unavailable_forced(old_id, ProbeDomain::Tcp, IpVersion::V4);
    assert!(
        !cp.alive_set
            .is_alive_for(old_id, ProbeDomain::Tcp, IpVersion::V4)
    );

    let fresh_chain = || Node::chain("via", vec!["front".into(), "land".into()]);
    let replacement = Node::from_share_link(&format!("socks5://{}#land", new_exit.addr))?;
    cp.merge_subscription_nodes(
        provider_id,
        vec![replacement.clone(), fresh_chain()],
        Vec::new(),
    )
    .await;

    let active = cp.config.read().await.clone();
    let new_id = named_node(&active, "via").id;
    assert_ne!(new_id, old_id);
    let selected = selected_tcp_v4(&cp, "pool");
    assert_eq!(selected, new_id);
    assert_eq!(active.groups[0].nodes, [new_id]);
    assert_eq!(active.groups[0].groups, ["alternative"]);
    let registered = cp.alive_set.registered_nodes();
    assert!(!registered.contains_key(&old_id));
    assert!(registered.contains_key(&new_id));
    assert!(
        cp.alive_set
            .is_alive_for(new_id, ProbeDomain::Tcp, IpVersion::V4)
    );
    assert!(history(old_id).is_empty());
    assert!(history(new_id).is_empty());

    let generation = cp.runtime_registry.read().clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?;
    let deadline = Duration::from_secs(5);
    let mut upstream = cp
        .proxy_registry
        .dial_runtime(Arc::clone(&generation), selected, target, None, deadline)
        .await?;
    tokio::time::timeout(deadline, async {
        let (mut peer, _) = listener.accept().await?;
        upstream.stream.write_all(b"new").await?;
        let mut payload = [0; 3];
        peer.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"new");
        Ok::<_, std::io::Error>(())
    })
    .await??;
    assert_eq!(*front.requests.lock(), [new_exit.addr]);
    assert_eq!(*new_exit.requests.lock(), [target]);
    assert!(old_exit.requests.lock().is_empty());

    let authorizations = SubscriptionAuthorizations::new(&active.subscriptions)?;
    let revision = authorizations.revision(provider_id).unwrap();
    let drain = DrainTracker::new();
    for (nodes, code) in [
        (
            vec![replacement, fresh_chain(), fresh_chain()],
            "duplicate-node-id",
        ),
        (vec![fresh_chain()], "invalid-chain-hop-reference"),
    ] {
        let error = cp
            .merge_authorized_subscription_nodes_with_drain(
                provider_id,
                revision,
                &authorizations,
                nodes,
                Vec::new(),
                &drain,
            )
            .await
            .unwrap_err();
        assert_eq!(error.diagnostic.code, code);
        assert!(Arc::ptr_eq(&*cp.config.read().await, &active));
        assert!(Arc::ptr_eq(&cp.runtime_registry.read(), &generation));
        assert_eq!(selected_tcp_v4(&cp, "pool"), new_id);
    }
    Ok(())
}

#[tokio::test]
async fn public_provider_refresh_ignores_foreign_and_physical_membership_aliases() {
    let foreign = subscription(31, "foreign", None);
    let provider = subscription(32, "refresh", Some("refresh-ua"));
    let provider_id = provider.id;
    let mut config = honk_config::parser::parse_dae_config(
        "global { nfqueue_enable: false }
         node {
             front: 'socks5://127.0.0.1:1080'
             land: 'socks5://127.0.0.1:1081'
             stale: 'socks5://127.0.0.1:1083'
             via: front -> land
         }",
    )
    .unwrap()
    .assemble(honk_config::parser::resolve_programmatic_groups)
    .unwrap();
    let foreign_id = named_node(&config, "via").id;
    let stale_id = named_node(&config, "stale").id;
    for node in &mut config.nodes {
        match node.name.as_str() {
            "via" => node.subscription_id = Some(foreign.id),
            "stale" => node.subscription_id = Some(provider_id),
            _ => {}
        }
    }
    config.subscriptions = vec![foreign, provider];
    config.groups = vec![
        Group {
            name: "foreign-pool".into(),
            nodes: vec![foreign_id],
            policy: GroupPolicy::Fallback,
            ..Default::default()
        },
        Group {
            name: "physical-pool".into(),
            nodes: vec![stale_id],
            policy: GroupPolicy::Fallback,
            final_outbound: Some("block".into()),
            ..Default::default()
        },
    ];
    let cp = crate::control::tests::support::control_plane(config);
    assert_eq!(selected_tcp_v4(&cp, "foreign-pool"), foreign_id);
    assert_eq!(selected_tcp_v4(&cp, "physical-pool"), stale_id);

    for (name, claimed_id) in [("stale", stale_id), ("other", foreign_id)] {
        let mut chain = Node::chain(name, vec!["land".into(), "front".into()]);
        chain.id = claimed_id;
        cp.merge_subscription_nodes(provider_id, vec![chain], Vec::new())
            .await;

        let active = cp.config.read().await;
        assert_ne!(named_node(&active, name).id, claimed_id);
        assert_eq!(active.groups[0].nodes, [foreign_id]);
        assert!(active.groups[1].nodes.is_empty());
        assert_eq!(selected_tcp_v4(&cp, "foreign-pool"), foreign_id);
        assert_eq!(selected_tcp_v4(&cp, "physical-pool"), BLOCK_NODE_ID);
    }
}
