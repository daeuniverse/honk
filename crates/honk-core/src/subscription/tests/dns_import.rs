use super::*;

const NODES: &str = "proxies:\n - { name: node, type: socks5, server: node.example, port: 1080 }\n";

#[test]
fn accepted_dns_source_survives_disabled_import_and_base64_detection() {
    let mut subscription = Subscription::default();
    let invalid = format!("{NODES}dns:\n nameserver: {{invalid: true}}\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(&invalid);
    let body =
        parse_subscription_body_with_diagnostics(&subscription, &encoded, &mut Vec::new()).unwrap();
    assert_eq!(body.nodes[0].host(), "node.example");
    assert!(body.accepted_dns_source.is_some());
    assert!(body.imported_dns.is_none());

    let clash_sub = Subscription {
        sub_type: SubscriptionType::Clash,
        ..Default::default()
    };
    let clash_body =
        parse_subscription_body_with_diagnostics(&clash_sub, &invalid, &mut Vec::new()).unwrap();
    assert!(clash_body.accepted_dns_source.is_some());

    let sing_box = r#"{
        "outbounds": [{"type": "socks", "tag": "sb", "server": "sb.example", "server_port": 1080}],
        "dns": {"servers": [{"address": "1.1.1.1"}]}
    }"#;
    let sb_sub = Subscription {
        import_dns: true,
        ..Default::default()
    };
    let sb_body =
        parse_subscription_body_with_diagnostics(&sb_sub, sing_box, &mut Vec::new()).unwrap();
    assert_eq!(sb_body.nodes[0].host(), "sb.example");
    assert!(sb_body.accepted_dns_source.is_none());
    assert!(sb_body.imported_dns.is_none());

    subscription.import_dns = true;
    let mut diagnostics = Vec::new();
    let error = parse_subscription_body_with_diagnostics(&subscription, &encoded, &mut diagnostics)
        .unwrap_err();
    assert_eq!(error.diagnostic.code, "invalid-subscription-dns");
    assert_eq!(diagnostics.last().unwrap().code, "invalid-subscription-dns");
    let good = format!("{NODES}dns:\n nameserver: 'tcp://192.0.2.53:5353'\n");
    let body =
        parse_subscription_body_with_diagnostics(&subscription, &good, &mut Vec::new()).unwrap();
    assert_eq!(
        body.imported_dns.unwrap().select("node.example").unwrap()[0].address,
        "192.0.2.53:5353"
    );
    assert!(
        parse_subscription_body_with_diagnostics(&subscription, NODES, &mut Vec::new())
            .unwrap()
            .accepted_dns_source
            .is_none()
    );
}

#[tokio::test]
async fn stored_dns_is_last_accepted_body_and_reparses_with_current_import_option() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(temp.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut subscription = Subscription {
        url: format!("http://{}/sub", listener.local_addr().unwrap()),
        download_detour: "direct".into(),
        import_dns: true,
        ..Default::default()
    };
    let server = tokio::spawn(async move {
        for dns in ["nameserver: 192.0.2.1", "nameserver: {invalid: true}"] {
            let body = format!("{NODES}dns:\n {dns}\n");
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let length = stream.read(&mut bytes).await.unwrap();
            assert!(length > 0);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    let manager = SubscriptionManager::new().unwrap();
    manager
        .fetch_and_store(&subscription, Some(&store))
        .await
        .unwrap();
    assert!(
        manager
            .fetch_and_store(&subscription, Some(&store))
            .await
            .is_err()
    );
    server.await.unwrap();
    let restored = store
        .load_body_with_diagnostics(&subscription, &mut Vec::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        restored.imported_dns.unwrap().nameservers[0].address,
        "192.0.2.1"
    );
    subscription.import_dns = false;
    let restored = store
        .load_body_with_diagnostics(&subscription, &mut Vec::new())
        .await
        .unwrap()
        .unwrap();
    assert!(restored.accepted_dns_source.is_some());
    assert!(restored.imported_dns.is_none());
}
