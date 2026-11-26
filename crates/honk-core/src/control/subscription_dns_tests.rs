use super::tests::support::control_plane;
use honk_config::{
    Config,
    node::{Group, GroupPolicy, Node},
    subscription::Subscription,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};

struct Fixture {
    address: SocketAddr,
    requests: Arc<parking_lot::Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn dns(address: Ipv4Addr) -> Fixture {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bound = socket.local_addr().unwrap();
    let requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let captured = requests.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let query = &bytes[..len];
            let mut offset = 12;
            let mut labels = Vec::new();
            while query[offset] != 0 {
                let length = usize::from(query[offset]);
                offset += 1;
                labels.push(std::str::from_utf8(&query[offset..offset + length]).unwrap());
                offset += length;
            }
            captured.lock().push(labels.join("."));
            offset += 1;
            let is_a = query[offset..offset + 2] == [0, 1];
            let mut answer = query[..offset + 4].to_vec();
            answer[2..4].copy_from_slice(&[0x81, 0x80]);
            answer[6..12].fill(0);
            if is_a {
                answer[7] = 1;
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
                answer.extend_from_slice(&address.octets());
            }
            socket.send_to(&answer, peer).await.unwrap();
        }
    });
    Fixture {
        address: bound,
        requests,
        task,
    }
}

async fn subscription_http(body: Arc<parking_lot::RwLock<String>>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let length = stream.read(&mut request).await.unwrap();
            assert!(length > 0);
            let body = body.read().clone();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    Fixture {
        address,
        requests: Default::default(),
        task,
    }
}

fn body(host: &str, port: u16, upstream: Option<SocketAddr>) -> String {
    let mut body = format!(
        "proxies:\n  - name: fixture\n    type: socks5\n    server: {host}\n    port: {port}\n"
    );
    if let Some(upstream) = upstream {
        body.push_str(&format!("dns:\n  nameserver: ['udp://{upstream}']\n"));
    }
    body
}

#[tokio::test]
async fn fetched_dns_and_nodes_publish_together_and_dns_only_refresh_changes_connection() {
    let first = dns(Ipv4Addr::new(127, 0, 0, 2)).await;
    let second = dns(Ipv4Addr::new(127, 0, 0, 3)).await;
    let fallback = dns(Ipv4Addr::new(127, 0, 0, 4)).await;
    let first_peer = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = first_peer.local_addr().unwrap().port();
    let second_peer = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 3), port))
        .await
        .unwrap();
    let source = Arc::new(parking_lot::RwLock::new(body(
        "node.example",
        port,
        Some(first.address),
    )));
    let http = subscription_http(source.clone()).await;
    let sub = Subscription {
        name: "fixture".into(),
        url: format!("http://{}/sub", http.address),
        download_detour: "direct".into(),
        import_dns: true,
        ..Default::default()
    };
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.global.bootstrap_resolver = fallback.address.to_string();
    config.subscriptions.push(sub.clone());
    config.ensure_builtin_nodes();
    let cp = control_plane(config);
    let manager = crate::subscription::SubscriptionManager::new().unwrap();
    let mut old_id = None;
    for (host, dns_server, expected, listener) in [
        (
            "node.example",
            &first,
            Ipv4Addr::new(127, 0, 0, 2),
            &first_peer,
        ),
        (
            "node.example",
            &second,
            Ipv4Addr::new(127, 0, 0, 3),
            &second_peer,
        ),
        (
            "replacement.example",
            &first,
            Ipv4Addr::new(127, 0, 0, 2),
            &first_peer,
        ),
    ] {
        *source.write() = body(host, port, Some(dns_server.address));
        let (content, _, _) = manager.fetch_content(&sub, &mut Vec::new()).await.unwrap();
        let node = content.nodes[0].clone();
        let previous_runtime = cp.runtime_registry.read().get(&node.id);
        if let Some(old) = old_id {
            if host == "node.example" {
                assert_eq!(node.id, old);
            } else {
                assert_ne!(node.id, old);
            }
        }
        old_id = Some(node.id);
        cp.merge_subscription_nodes(sub.id, content, Vec::new())
            .await;
        assert!(
            cp.config.read().await.subscriptions[0]
                .imported_dns
                .is_some()
        );
        let registry = cp.runtime_registry.read().clone();
        assert!(registry.get(&node.id).is_some());
        if let Some(previous) = previous_runtime {
            assert!(
                !Arc::ptr_eq(&previous, &registry.get(&node.id).unwrap()),
                "DNS change retained the old node's connection pools"
            );
        }
        let stream = registry
            .scope_node_dials(
                node.id,
                honk_outbound::util::connect_outbound(
                    &format!("{host}:{port}"),
                    Duration::from_secs(2),
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}; queries={:?}", dns_server.requests.lock()));
        assert_eq!(stream.peer_addr().unwrap().ip(), expected);
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(dns_server.requests.lock().iter().any(|name| name == host));
    }
    let generation = cp.runtime_registry.read().generation();
    *source.write() = format!("{}dns: broken\n", body("replacement.example", port, None));
    assert!(manager.fetch_content(&sub, &mut Vec::new()).await.is_err());
    assert_eq!(cp.runtime_registry.read().generation(), generation);
    assert!(
        cp.config.read().await.subscriptions[0]
            .imported_dns
            .is_some()
    );
    let registry = cp.runtime_registry.read().clone();
    let stream = registry
        .scope_node_dials(
            old_id.unwrap(),
            honk_outbound::util::connect_outbound(
                &format!("replacement.example:{port}"),
                Duration::from_secs(2),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        stream.peer_addr().unwrap().ip(),
        Ipv4Addr::new(127, 0, 0, 2)
    );
    *source.write() = body("replacement.example", port, None);
    let (content, _, _) = manager.fetch_content(&sub, &mut Vec::new()).await.unwrap();
    cp.merge_subscription_nodes(sub.id, content, Vec::new())
        .await;
    assert!(
        cp.config.read().await.subscriptions[0]
            .imported_dns
            .is_none()
    );
    assert_ne!(cp.runtime_registry.read().generation(), generation);
    let registry = cp.runtime_registry.read().clone();
    assert_eq!(
        registry
            .resolve_node_host(old_id.unwrap(), "replacement.example")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))]
    );
    assert!(
        fallback
            .requests
            .lock()
            .iter()
            .any(|host| host == "replacement.example")
    );
}

#[tokio::test]
async fn cached_body_and_sighup_keep_the_accepted_dns_source() {
    let first = dns(Ipv4Addr::new(127, 0, 0, 2)).await;
    let newer = dns(Ipv4Addr::new(127, 0, 0, 3)).await;
    let source = Arc::new(parking_lot::RwLock::new(body(
        "cached.example",
        1080,
        Some(first.address),
    )));
    let http = subscription_http(source.clone()).await;
    let sub = Subscription {
        name: "cached".into(),
        url: format!("http://{}/sub", http.address),
        download_detour: "direct".into(),
        import_dns: true,
        ..Default::default()
    };
    let temp = tempfile::tempdir().unwrap();
    let store = crate::subscription::SubscriptionStore::in_dir(temp.path());
    let manager = crate::subscription::SubscriptionManager::new().unwrap();
    manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
    let content = store
        .load_body_with_diagnostics(&sub, &mut Vec::new())
        .await
        .unwrap()
        .unwrap();
    let node_id = content.nodes[0].id;
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.subscriptions.push(sub.clone());
    content.publish_dns(&mut config.subscriptions[0]);
    config.nodes.extend(content.nodes);
    config.ensure_builtin_nodes();
    let cp = control_plane(config);
    let registry = cp.runtime_registry.read().clone();
    let addresses = registry
        .scope_node_dials(
            node_id,
            honk_outbound::bootstrap::resolve_node("cached.example"),
        )
        .await
        .unwrap();
    assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
    *source.write() = body("cached.example", 1080, Some(newer.address));
    manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
    let mut replacement = Config::default();
    replacement.global.nfqueue_enable = false;
    replacement.ensure_builtin_nodes();
    replacement.subscriptions.push(sub.clone());
    let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(&[sub]).unwrap();
    let outcome = cp
        .apply_sighup_config(
            replacement,
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(outcome.accepted());
    assert!(
        cp.config.read().await.subscriptions[0]
            .imported_dns
            .is_some()
    );
    let registry = cp.runtime_registry.read().clone();
    let addresses = registry
        .scope_node_dials(
            node_id,
            honk_outbound::bootstrap::resolve_node("cached.example"),
        )
        .await
        .unwrap();
    assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
    assert!(newer.requests.lock().is_empty());

    let old_revision = authorizations
        .revision(cp.config.read().await.subscriptions[0].id)
        .unwrap();
    for enable in [false, true] {
        let mut replacement = (**cp.config.read().await).clone();
        replacement.subscriptions[0].import_dns = enable;
        let outcome = cp
            .apply_sighup_config(
                replacement,
                Vec::new(),
                &super::DrainTracker::new(),
                &mut authorizations,
                #[cfg(feature = "native-api")]
                None,
                #[cfg(feature = "native-api")]
                None,
            )
            .await
            .unwrap();
        assert!(outcome.accepted());
        if !enable {
            let generation = cp.runtime_registry.read().generation();
            let sub = cp.config.read().await.subscriptions[0].clone();
            let (content, _, _) = manager.fetch_content(&sub, &mut Vec::new()).await.unwrap();
            cp.merge_subscription_nodes(sub.id, content, Vec::new())
                .await;
            assert_eq!(
                generation,
                cp.runtime_registry.read().generation(),
                "disabled DNS-only update rebuilt runtime"
            );
            assert!(
                cp.config.read().await.subscriptions[0]
                    .imported_dns
                    .is_none()
            );
        }
    }
    let registry = cp.runtime_registry.read().clone();
    assert_eq!(
        registry
            .resolve_node_host(node_id, "cached.example")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]
    );
    assert!(
        newer
            .requests
            .lock()
            .iter()
            .any(|host| host == "cached.example")
    );
    let sub = cp.config.read().await.subscriptions[0].clone();
    *source.write() = body("cached.example", 1080, Some(first.address));
    let (stale, _, _) = manager.fetch_content(&sub, &mut Vec::new()).await.unwrap();
    let generation = registry.generation();
    let outcome = cp
        .merge_authorized_subscription_nodes_with_drain(
            sub.id,
            old_revision,
            &authorizations,
            stale,
            Vec::new(),
            &super::DrainTracker::new(),
        )
        .await
        .unwrap();
    assert!(
        !outcome.accepted(),
        "old refresh authorization survived an import toggle"
    );
    assert_eq!(cp.runtime_registry.read().generation(), generation);
}

async fn socks5_tcp_relay(
    bind_addr: &str,
    domain_override: Option<(&'static str, SocketAddr)>,
) -> Fixture {
    let listener = TcpListener::bind(bind_addr).await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let task = tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let captured = Arc::clone(&captured);
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.unwrap();
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.unwrap();
                client.write_all(&[0x05, 0x00]).await.unwrap();

                let mut head = [0u8; 4];
                client.read_exact(&mut head).await.unwrap();
                assert_eq!(head[1], 0x01);
                let target = match head[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        client.read_exact(&mut ip).await.unwrap();
                        let port = client.read_u16().await.unwrap();
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
                    }
                    0x03 => {
                        let len = usize::from(client.read_u8().await.unwrap());
                        let mut host = vec![0u8; len];
                        client.read_exact(&mut host).await.unwrap();
                        let host = String::from_utf8(host).unwrap();
                        let port = client.read_u16().await.unwrap();
                        captured.lock().push(host.clone());
                        let (expected_host, mapped) = domain_override.unwrap();
                        assert_eq!(host, expected_host);
                        assert_eq!(port, mapped.port());
                        mapped
                    }
                    other => panic!("unexpected SOCKS5 atyp {other}"),
                };
                let mut upstream = TcpStream::connect(target).await.unwrap();
                client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    Fixture {
        address,
        requests: seen,
        task,
    }
}

#[tokio::test]
async fn chain_and_group_exit_entry_hops_use_hop_zero_subscription_dns_without_resolving_tunnel_hops()
 {
    let entry_dns = dns(Ipv4Addr::new(127, 0, 0, 2)).await;
    let exit_dns = dns(Ipv4Addr::new(127, 0, 0, 99)).await;
    let unconfigured_bootstrap = dns(Ipv4Addr::new(127, 0, 0, 98)).await;

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(&buf[..n]).await.unwrap();
            });
        }
    });

    let exit_hop = socks5_tcp_relay("127.0.0.3:0", None).await;
    let entry_hop =
        socks5_tcp_relay("127.0.0.2:0", Some(("exit.chain.test", exit_hop.address))).await;

    let entry_sub = Subscription {
        name: "entry-sub".into(),
        url: "https://entry.invalid/sub".into(),
        import_dns: true,
        imported_dns: honk_config::subscription::dns::SubscriptionDns::parse(
            &serde_yaml::from_str(&format!("nameserver: ['udp://{}']", entry_dns.address)).unwrap(),
        )
        .unwrap()
        .map(Arc::new),
        ..Default::default()
    };
    let exit_sub = Subscription {
        name: "exit-sub".into(),
        url: "https://exit.invalid/sub".into(),
        import_dns: true,
        imported_dns: honk_config::subscription::dns::SubscriptionDns::parse(
            &serde_yaml::from_str(&format!("nameserver: ['udp://{}']", exit_dns.address)).unwrap(),
        )
        .unwrap()
        .map(Arc::new),
        ..Default::default()
    };

    let mut entry_node = Node::from_share_link(&format!(
        "socks5://entry.chain.test:{}#entry",
        entry_hop.address.port()
    ))
    .unwrap();
    entry_node.subscription_id = Some(entry_sub.id);

    let mut exit_node = Node::from_share_link(&format!(
        "socks5://exit.chain.test:{}#exit",
        exit_hop.address.port()
    ))
    .unwrap();
    exit_node.subscription_id = Some(exit_sub.id);

    let chain_node = Node::chain("chained", vec!["entry".into(), "exit".into()]);

    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.global.bootstrap_resolver = unconfigured_bootstrap.address.to_string();
    config.subscriptions = vec![entry_sub, exit_sub];
    config.nodes = vec![entry_node.clone(), exit_node.clone(), chain_node];
    config.groups.push(Group {
        name: "via-exit".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![entry_node.id],
        exit: Some("exit".into()),
        ..Default::default()
    });
    config.ensure_builtin_nodes();
    config = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();
    let chain_id = config
        .nodes
        .iter()
        .find(|n| n.name == "chained")
        .unwrap()
        .id;

    let cp = control_plane(config);
    let generation = cp.runtime_registry.read().clone();

    let mut stream = cp
        .proxy_registry
        .dial_runtime(
            generation.clone(),
            chain_id,
            echo_addr,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    stream.stream.write_all(b"chain-ping").await.unwrap();
    let mut reply = [0u8; 10];
    stream.stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"chain-ping");

    let route = {
        let manager = cp.group_manager.read();
        let ctx = honk_outbound::group::ScoreSelectionContext::aggregate(
            honk_outbound::group::SelectionNetwork::Tcp,
            honk_outbound::alive::ProbeDomain::Tcp,
            honk_outbound::alive::IpVersion::V4,
        );
        let plan = manager.selection_plan_for_target_with_health_fallback("via-exit", &ctx, None);
        *plan.entries[0].route.as_deref().unwrap()
    };
    let mut exit_stream = cp
        .proxy_registry
        .dial_ref(
            generation,
            honk_outbound::proxy::DialRef::Route(&route),
            echo_addr,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    exit_stream.stream.write_all(b"exit-ping!").await.unwrap();
    exit_stream.stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"exit-ping!");

    assert!(
        entry_dns
            .requests
            .lock()
            .iter()
            .any(|q| q == "entry.chain.test")
    );
    assert!(
        exit_dns.requests.lock().is_empty(),
        "hops[1] hostname was resolved locally instead of tunneled: {:?}",
        exit_dns.requests.lock()
    );
    assert!(
        unconfigured_bootstrap.requests.lock().is_empty(),
        "entry hop fell back to global bootstrap instead of entry_sub's imported DNS"
    );
    assert_eq!(entry_hop.requests.lock().len(), 2);
    echo_task.abort();
}

#[tokio::test]
async fn noop_refresh_preserves_config_identity_and_group_ids_while_programmatic_reload_toggles_and_retires_imported_dns()
 {
    let provider_dns = dns(Ipv4Addr::new(127, 0, 0, 2)).await;
    let bootstrap_dns = dns(Ipv4Addr::new(127, 0, 0, 4)).await;
    let source = Arc::new(parking_lot::RwLock::new(body(
        "first.example",
        1080,
        Some(provider_dns.address),
    )));
    let http = subscription_http(source.clone()).await;

    let sub1 = Subscription {
        name: "sub1".into(),
        url: format!("http://{}/sub", http.address),
        download_detour: "direct".into(),
        import_dns: false,
        ..Default::default()
    };
    let sub2 = Subscription {
        name: "sub2".into(),
        url: "https://sub2.invalid/sub".into(),
        download_detour: "direct".into(),
        import_dns: false,
        ..Default::default()
    };
    let manager = crate::subscription::SubscriptionManager::new().unwrap();
    let (initial1, _, _) = manager.fetch_content(&sub1, &mut Vec::new()).await.unwrap();
    let mut node2 = Node::from_share_link("socks5://second.example:1081#second").unwrap();
    node2.subscription_id = Some(sub2.id);

    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.global.bootstrap_resolver = bootstrap_dns.address.to_string();
    config.subscriptions = vec![sub1.clone(), sub2.clone()];
    initial1.publish_dns(&mut config.subscriptions[0]);
    config.nodes = vec![initial1.nodes[0].clone(), node2.clone()];
    config.groups = honk_config::parser::parse_dae_config(
        "group {\n all-subs {\n filter: subtag(keyword: sub)\n }\n}\n",
    )
    .unwrap()
    .groups;
    config.ensure_builtin_nodes();
    config = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();

    let cp = control_plane(config);
    let before_arc = cp.config.read().await.clone();
    let before_group_id = before_arc.groups[0].id;
    let before_node_order = before_arc
        .nodes
        .iter()
        .map(|n| n.name.clone())
        .collect::<Vec<_>>();
    let node1_id = initial1.nodes[0].id;

    let (same_content, _, _) = manager.fetch_content(&sub1, &mut Vec::new()).await.unwrap();
    cp.merge_subscription_nodes(sub1.id, same_content, Vec::new())
        .await;
    let after_same = cp.config.read().await.clone();
    assert!(
        Arc::ptr_eq(&before_arc, &after_same),
        "identical Noop refresh unnecessarily cloned Config"
    );
    assert!(cp.active_routing_plan.read().manager_matches(&after_same));

    let second_dns = dns(Ipv4Addr::new(127, 0, 0, 3)).await;
    *source.write() = body("first.example", 1080, Some(second_dns.address));
    let (updated_source_only, _, _) = manager.fetch_content(&sub1, &mut Vec::new()).await.unwrap();
    cp.merge_subscription_nodes(sub1.id, updated_source_only, Vec::new())
        .await;
    let after_source_change = cp.config.read().await.clone();
    assert_eq!(after_source_change.groups[0].id, before_group_id);
    assert_eq!(
        after_source_change
            .nodes
            .iter()
            .map(|n| n.name.clone())
            .collect::<Vec<_>>(),
        before_node_order,
        "Noop accepted_dns_source update reordered multi-subscription nodes"
    );
    assert!(
        cp.active_routing_plan
            .read()
            .manager_matches(&after_source_change)
    );

    let mut direct_toggle = (*after_source_change).clone();
    direct_toggle.subscriptions[0].import_dns = true;
    let rejected = cp
        .apply_runtime_config(
            direct_toggle,
            Default::default(),
            &super::DrainTracker::new(),
        )
        .await;
    assert!(
        !rejected.accepted(),
        "mutating import_dns without SIGHUP worker authorizations must be rejected"
    );

    let mut authorizations =
        crate::subscription::SubscriptionAuthorizations::new(&after_source_change.subscriptions)
            .unwrap();
    let mut sighup_enabled = Config::default();
    sighup_enabled.global.nfqueue_enable = false;
    sighup_enabled.global.bootstrap_resolver = bootstrap_dns.address.to_string();
    sighup_enabled.subscriptions = vec![
        Subscription {
            import_dns: true,
            ..sub1.clone()
        },
        sub2.clone(),
    ];
    sighup_enabled.nodes = vec![node2.clone()];
    sighup_enabled.groups = honk_config::parser::parse_dae_config(
        "group {\n all-subs {\n filter: subtag(keyword: sub)\n }\n}\n",
    )
    .unwrap()
    .groups;
    sighup_enabled.ensure_builtin_nodes();
    let outcome = cp
        .apply_sighup_config(
            sighup_enabled,
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(outcome.accepted());
    let enabled_generation = cp.runtime_registry.read().clone();
    assert_eq!(
        enabled_generation
            .resolve_node_host(node1_id, "first.example")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]
    );

    let mut recompiled = (**cp.config.read().await).clone();
    recompiled.subscriptions[0].imported_dns = None;
    let outcome = cp
        .apply_runtime_config(recompiled, Default::default(), &super::DrainTracker::new())
        .await;
    assert!(outcome.accepted());
    assert!(
        cp.config.read().await.subscriptions[0]
            .imported_dns
            .is_some()
    );

    let mut sighup_disabled = (**cp.config.read().await).clone();
    sighup_disabled.nodes = vec![node2];
    sighup_disabled.subscriptions[0].import_dns = false;
    sighup_disabled.subscriptions[0].accepted_dns_source = None;
    sighup_disabled.subscriptions[0].imported_dns = None;
    sighup_disabled.ensure_builtin_nodes();
    let outcome = cp
        .apply_sighup_config(
            sighup_disabled,
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(outcome.accepted());
    let disabled_generation = cp.runtime_registry.read().clone();
    assert_eq!(
        disabled_generation
            .resolve_node_host(node1_id, "first.example")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))]
    );
}

#[tokio::test]
async fn sighup_use_host_file_edit_rotates_node_runtimes_and_updates_alias_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let hosts_path = dir.path().join("hosts");
    std::fs::write(
        &hosts_path,
        "aliased.node.test target-one.hosts.test\ntarget-one.hosts.test 127.0.0.2\n",
    )
    .unwrap();

    let node = Node::from_share_link("socks5://aliased.node.test:1080#aliased").unwrap();
    let node_id = node.id;
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.dns.hosts = vec![hosts_path.to_string_lossy().into_owned()];
    config.nodes = vec![node];
    config.ensure_builtin_nodes();

    let cp = control_plane(config.clone());
    let mut authorizations =
        crate::subscription::SubscriptionAuthorizations::new(&config.subscriptions).unwrap();

    let first = cp
        .apply_sighup_config(
            config.clone(),
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(first.accepted());
    let gen1 = cp.runtime_registry.read().clone();
    let rt1 = gen1.get(&node_id).unwrap();
    assert_eq!(
        gen1.resolve_node_host(node_id, "aliased.node.test")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]
    );

    let mut routing_only = config.clone();
    routing_only
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: "unrelated".into(),
            condition: honk_config::routing::RoutingCondition {
                domain: vec!["unrelated.example".into()],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
    let second = cp
        .apply_sighup_config(
            routing_only.clone(),
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(second.accepted());
    let rt2 = cp.runtime_registry.read().get(&node_id).unwrap();
    assert!(
        Arc::ptr_eq(&rt1, &rt2),
        "unchanged hosts_snapshot unexpectedly rotated NodeRuntime"
    );

    std::fs::write(
        &hosts_path,
        "aliased.node.test target-two-updated.hosts.test\ntarget-two-updated.hosts.test 127.0.0.3\n",
    )
    .unwrap();
    let third = cp
        .apply_sighup_config(
            routing_only,
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(third.accepted());
    let gen3 = cp.runtime_registry.read().clone();
    let rt3 = gen3.get(&node_id).unwrap();
    assert!(
        !Arc::ptr_eq(&rt2, &rt3),
        "editing dns.use_host on disk failed to rotate NodeRuntime"
    );
    assert_eq!(
        gen3.resolve_node_host(node_id, "aliased.node.test")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]
    );
}

#[tokio::test]
async fn full_reload_and_provider_reorder_preserve_disabled_accepted_dns_sources() {
    let sub1_old_dns = dns(Ipv4Addr::new(127, 0, 0, 2)).await;
    let sub1_new_dns = dns(Ipv4Addr::new(127, 0, 0, 3)).await;
    let sub2_dns = dns(Ipv4Addr::new(127, 0, 0, 4)).await;
    let bootstrap_dns = dns(Ipv4Addr::new(127, 0, 0, 5)).await;

    let source1 = Arc::new(parking_lot::RwLock::new(body(
        "first.example",
        1080,
        Some(sub1_old_dns.address),
    )));
    let source2 = Arc::new(parking_lot::RwLock::new(body(
        "second.example",
        2080,
        Some(sub2_dns.address),
    )));
    let http1 = subscription_http(source1.clone()).await;
    let http2 = subscription_http(source2).await;

    let sub1 = Subscription {
        name: "sub1".into(),
        url: format!("http://{}/sub1", http1.address),
        download_detour: "direct".into(),
        import_dns: false,
        ..Default::default()
    };
    let sub2 = Subscription {
        name: "sub2".into(),
        url: format!("http://{}/sub2", http2.address),
        download_detour: "direct".into(),
        import_dns: false,
        ..Default::default()
    };
    let manager = crate::subscription::SubscriptionManager::new().unwrap();
    let (initial1, _, _) = manager.fetch_content(&sub1, &mut Vec::new()).await.unwrap();
    let (initial2, _, _) = manager.fetch_content(&sub2, &mut Vec::new()).await.unwrap();

    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.global.bootstrap_resolver = bootstrap_dns.address.to_string();
    config.subscriptions = vec![sub1.clone(), sub2.clone()];
    initial1.publish_dns(&mut config.subscriptions[0]);
    initial2.publish_dns(&mut config.subscriptions[1]);
    config.nodes = vec![initial1.nodes[0].clone(), initial2.nodes[0].clone()];
    config.ensure_builtin_nodes();
    config = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();

    let cp = control_plane(config);
    let node2_id = initial2.nodes[0].id;

    *source1.write() = body("first.example", 1081, Some(sub1_new_dns.address));
    let (refreshed1, _, _) = manager.fetch_content(&sub1, &mut Vec::new()).await.unwrap();
    let refreshed1_dns_source = refreshed1.accepted_dns_source.clone();
    let node1_new_id = refreshed1.nodes[0].id;
    cp.merge_subscription_nodes(sub1.id, refreshed1, Vec::new())
        .await;

    let current = cp.config.read().await.clone();
    assert_eq!(
        current.subscriptions[0].accepted_dns_source,
        refreshed1_dns_source
    );
    let mut authorizations =
        crate::subscription::SubscriptionAuthorizations::new(&current.subscriptions).unwrap();

    let mut reordered = Config::default();
    reordered.global.nfqueue_enable = false;
    reordered.global.bootstrap_resolver = bootstrap_dns.address.to_string();
    reordered.subscriptions = vec![sub2.clone(), sub1.clone()];
    reordered.ensure_builtin_nodes();
    let outcome = cp
        .apply_sighup_config(
            reordered,
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(outcome.accepted());

    let mut enabled = Config::default();
    enabled.global.nfqueue_enable = false;
    enabled.global.bootstrap_resolver = bootstrap_dns.address.to_string();
    enabled.subscriptions = vec![
        Subscription {
            import_dns: true,
            ..sub2.clone()
        },
        Subscription {
            import_dns: true,
            ..sub1.clone()
        },
    ];
    enabled.ensure_builtin_nodes();
    let outcome = cp
        .apply_sighup_config(
            enabled,
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(outcome.accepted());

    let active_reg = cp.runtime_registry.read().clone();
    assert_eq!(
        active_reg
            .resolve_node_host(node1_new_id, "first.example")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]
    );
    assert_eq!(
        active_reg
            .resolve_node_host(node2_id, "second.example")
            .await
            .unwrap(),
        [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))]
    );
    assert!(sub1_old_dns.requests.lock().is_empty());
    assert!(bootstrap_dns.requests.lock().is_empty());
}

#[tokio::test]
async fn retired_socks_health_relay_keeps_dns_authority() {
    let provider_dns = dns(Ipv4Addr::new(127, 0, 0, 2)).await;
    let bootstrap_dns = dns(Ipv4Addr::new(127, 0, 0, 9)).await;

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let associate_entered = Arc::new(tokio::sync::Notify::new());
    let release_associate = Arc::new(tokio::sync::Notify::new());
    let entered_server = Arc::clone(&associate_entered);
    let release_server = Arc::clone(&release_associate);
    let socks_task = tokio::spawn(async move {
        let (mut stream, _) = socks_listener.accept().await.unwrap();
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        let mut methods = vec![0u8; usize::from(greeting[1])];
        stream.read_exact(&mut methods).await.unwrap();
        stream.write_all(&[0x05, 0x00]).await.unwrap();

        let mut req_head = [0u8; 4];
        stream.read_exact(&mut req_head).await.unwrap();
        assert_eq!(req_head[1], 0x03);
        let skip = match req_head[3] {
            0x01 => 6,
            0x04 => 18,
            _ => unreachable!(),
        };
        let mut req_rest = vec![0u8; skip];
        stream.read_exact(&mut req_rest).await.unwrap();

        entered_server.notify_one();
        release_server.notified().await;

        let relay_domain = b"relay.provider.test";
        let mut reply = vec![0x05, 0x00, 0x00, 0x03, relay_domain.len() as u8];
        reply.extend_from_slice(relay_domain);
        reply.extend_from_slice(&5353u16.to_be_bytes());
        stream.write_all(&reply).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let source = Arc::new(parking_lot::RwLock::new(body(
        &socks_addr.ip().to_string(),
        socks_addr.port(),
        Some(provider_dns.address),
    )));
    let http = subscription_http(source).await;
    let sub = Subscription {
        name: "socks-sub".into(),
        url: format!("http://{}/sub", http.address),
        download_detour: "direct".into(),
        import_dns: true,
        ..Default::default()
    };
    let manager = crate::subscription::SubscriptionManager::new().unwrap();
    let (initial, _, _) = manager.fetch_content(&sub, &mut Vec::new()).await.unwrap();
    let node = initial.nodes[0].clone();
    let node_id = node.id;

    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.global.bootstrap_resolver = bootstrap_dns.address.to_string();
    config.global.udp_check_dns = Some(vec!["127.0.0.1:53".into()]);
    config.subscriptions = vec![sub.clone()];
    initial.publish_dns(&mut config.subscriptions[0]);
    config.nodes = vec![node.clone()];
    config.groups = vec![Group {
        name: "proxy".into(),
        policy: GroupPolicy::Selector,
        nodes: vec![node_id],
        ..Default::default()
    }];
    config.ensure_builtin_nodes();
    config = config
        .assemble(honk_config::parser::resolve_group_filters)
        .unwrap();

    let cp = control_plane(config.clone());
    let alive = cp.alive_set();
    alive.register_node(node_id, node.name.clone(), Some(node.address.clone()));
    alive.set_udp_probe(Arc::new(super::probers::ProxyUdpProber::new(
        cp.config.clone(),
        cp.proxy_registry.clone(),
        cp.runtime_registry.clone(),
        cp.stats.clone(),
        super::probers::UdpDnsProbeTarget::new(vec!["127.0.0.1:53".into()], None),
        None,
        cp.group_manager.clone(),
    )));

    let probe_alive = Arc::clone(&alive);
    let probe_handle = tokio::spawn(async move {
        probe_alive
            .probe_node_udp(node_id, Duration::from_secs(2))
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), associate_entered.notified())
        .await
        .expect("UDP probe must reach SOCKS5 UDP ASSOCIATE");

    let mut reloaded = config.clone();
    reloaded
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: "rotate".into(),
            condition: honk_config::routing::RoutingCondition {
                domain: vec!["rotate.example".into()],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
    let mut authorizations =
        crate::subscription::SubscriptionAuthorizations::new(&config.subscriptions).unwrap();
    let outcome = cp
        .apply_sighup_config(
            reloaded,
            Vec::new(),
            &super::DrainTracker::new(),
            &mut authorizations,
            #[cfg(feature = "native-api")]
            None,
            #[cfg(feature = "native-api")]
            None,
        )
        .await
        .unwrap();
    assert!(outcome.accepted());
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }

    release_associate.notify_one();
    let ok = probe_handle.await.unwrap();
    assert!(!ok);
    assert!(
        bootstrap_dns.requests.lock().is_empty(),
        "retired SOCKS5 relay domain leaked to bootstrap DNS: {:?}",
        bootstrap_dns.requests.lock()
    );
    assert!(
        !alive.has_udp_state(node_id),
        "cancelled retired generation probe must stay health-neutral"
    );
    socks_task.abort();
}
