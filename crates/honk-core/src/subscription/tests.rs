use super::*;
use base64::Engine as _;
use honk_config::types::NodeProtocol;

mod clash;

fn parse_clash_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let yaml = parse_structured_value(content)?;
    let proxies = yaml
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("no 'proxies' array found in Clash YAML"))?;
    parse_clash_proxies(proxies, subscription_id)
}

#[tokio::test]
async fn body_reader_refuses_one_byte_past_the_cap() {
    let at_cap = http::Response::new(vec![b'a'; MAX_SUBSCRIPTION_BYTES]);
    assert_eq!(
        read_capped_body(at_cap.into()).await.unwrap().len(),
        MAX_SUBSCRIPTION_BYTES
    );
    let over_cap = http::Response::new(vec![b'a'; MAX_SUBSCRIPTION_BYTES + 1]);
    assert!(read_capped_body(over_cap.into()).await.is_err());
}

#[test]
fn private_literal_hosts_are_recognized_by_address_not_name() {
    for url in [
        "http://127.0.0.1/sub",
        "http://10.203.0.1:8080/sub",
        "http://192.168.1.1/sub",
        "http://169.254.1.1/sub",
        "http://[::1]/sub",
        "http://[fd00::1]/sub",
        "http://[fe80::1]/sub",
        "http://[::ffff:127.0.0.1]/sub",
        "http://0.0.0.0/sub",
        "http://[::]/sub",
    ] {
        let url = reqwest::Url::parse(url).unwrap();
        assert!(has_private_literal_host(&url), "{url} should be private");
    }
    for url in [
        "https://example.com/sub",
        "http://93.184.216.34/sub",
        "http://[2001:db8::1]/sub",
        // Resolution is out of scope: only a stated literal is refused.
        "http://internal.example/sub",
    ] {
        let url = reqwest::Url::parse(url).unwrap();
        assert!(
            !has_private_literal_host(&url),
            "{url} should not be private"
        );
    }
}

#[test]
fn test_parse_base64_subscription() {
    let uris = [
        "socks5://192.168.1.1:1080#Node1",
        "socks5://10.0.0.1:2080#Node2",
    ];
    let joined = uris.join("\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &encoded,
    )
    .unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].name, "Node1");
    assert_eq!(nodes[1].name, "Node2");
    assert_eq!(nodes[0].protocol(), NodeProtocol::Socks5);
    assert_eq!(nodes[1].protocol(), NodeProtocol::Socks5);
}

#[test]
fn uri_subscription_with_empty_vmess_remark_remains_usable() {
    let payload = r#"{"ps":"","add":"vmess.example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}"#;
    let uri = format!(
        "vmess://{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
    );
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &uri,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].protocol(), NodeProtocol::VMess);
    assert_eq!(nodes[0].name, "vmess-vmess.example.com");
}

#[test]
fn test_parse_base64_without_padding() {
    let uris = "socks5://10.0.0.1:1080#NoPad";
    let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
    let no_pad = encoded.trim_end_matches('=');
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        no_pad,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "NoPad");
}

#[test]
fn test_parse_base64_skips_unsupported() {
    let uris = ["socks5://192.168.1.1:1080#Valid", "unknown://host:1234"];
    let joined = uris.join("\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    let nodes = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &encoded,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "Valid");
}

#[test]
fn test_parse_base64_empty_result() {
    let uris = "unknown://host:1234\nanother-unsupported://x:1";
    let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
    let result = parse_subscription_content(
        &Subscription {
            sub_type: SubscriptionType::Simple,
            ..Default::default()
        },
        &encoded,
    );
    assert!(result.is_err());
}

#[test]
fn subscription_normalizes_bom_and_urlsafe_wrapped_base64() {
    let sub = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let uri = "socks5://127.0.0.1:1080#wrapped";
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uri);
    let wrapped = encoded
        .as_bytes()
        .chunks(7)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" \n");
    let nodes = parse_subscription_content(&sub, &format!("\u{feff}{wrapped}")).unwrap();
    assert_eq!(nodes[0].name, "wrapped");
}

#[test]
fn simple_and_custom_detect_structured_bodies_without_fallback() {
    let yaml =
        "proxies:\n  - type: socks5\n    server: 127.0.0.1\n    port: 1080\n    name: yaml\n";
    let simple = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    assert_eq!(
        parse_subscription_content(&simple, yaml).unwrap()[0].name,
        "yaml"
    );

    let custom = Subscription {
        sub_type: SubscriptionType::Custom,
        ..Default::default()
    };
    let json =
        r#"{"outbounds":[{"type":"socks","tag":"json","server":"127.0.0.1","server_port":1081}]}"#;
    assert_eq!(
        parse_subscription_content(&custom, json).unwrap()[0].name,
        "json"
    );
    assert!(parse_subscription_content(&simple, r#"{"unknown":"wrapper"}"#).is_err());
    assert!(
        parse_subscription_content(
            &simple,
            "{\"outbounds\":[\ntrojan://secret@example.com:443#not-json",
        )
        .is_err()
    );
}

#[test]
fn explicit_sip008_uses_server_schema_not_uri_parser() {
    let sub = Subscription {
        sub_type: SubscriptionType::Sip008,
        ..Default::default()
    };
    let body = r#"{"servers":[{"server":"ss.example","server_port":8388,"method":"aes-128-gcm","password":"secret","remarks":"sip"}]}"#;
    let nodes = parse_subscription_content(&sub, body).unwrap();
    assert_eq!(nodes[0].name, "sip");
    assert_eq!(nodes[0].protocol(), NodeProtocol::SS);
}

#[test]
fn json_subscription_names_accept_utf16_surrogate_pairs() {
    for (sub_type, body) in [
        (
            SubscriptionType::Simple,
            r#"{"outbounds":[{"type":"socks","tag":"node-\ud83d\ude00","server":"127.0.0.1","server_port":1080}]}"#,
        ),
        (
            SubscriptionType::Clash,
            r#"{"proxies":[{"type":"socks5","name":"node-\ud83d\ude00","server":"127.0.0.1","port":1080}]}"#,
        ),
        (
            SubscriptionType::Sip008,
            r#"{"servers":[{"remarks":"node-\ud83d\ude00","server":"127.0.0.1","server_port":8388,"method":"aes-128-gcm","password":"fixture"}]}"#,
        ),
    ] {
        let sub = Subscription {
            sub_type,
            ..Default::default()
        };
        let nodes = parse_subscription_content(&sub, body).unwrap();
        assert_eq!(nodes[0].name, "node-\u{1f600}");
    }
}

#[test]
fn test_parse_subscription_keeps_unique_nodes_with_duplicates() {
    let sub = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let content = concat!(
        "socks5://127.0.0.1:1080#same\n",
        "socks5://127.0.0.1:1080#same-again"
    );
    let nodes = parse_subscription_content(&sub, content).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "same");
}

#[test]
fn test_parse_subscription_keeps_valid_sibling_after_intrinsic_rejection() {
    let invalid = "vless://00000000-0000-4000-8000-000000000001@h:443?encryption=e&type=ws&sni=ws&flow=xudp#a";
    let valid = "vless://00000000-0000-4000-8000-000000000001@h:443?type=ws&sni=u&path=ws&vless_mode=xudp#b";
    let sub = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let nodes = parse_subscription_content(&sub, &format!("{invalid}\n{valid}")).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["b"]
    );
    let error = Node::from_share_link(invalid).unwrap_err();
    assert!(matches!(error, honk_config::ConfigError::Validation(_)));
}

#[test]
fn test_parse_subscription_skips_proxy_plugins() {
    let clash = Subscription {
        sub_type: SubscriptionType::Clash,
        ..Default::default()
    };
    let clash_nodes = parse_subscription_content(
        &clash,
        r#"proxies:
  - name: obfs
    type: ss
    server: ss.example
    port: 8388
    cipher: aes-128-gcm
    password: secret
    plugin: obfs
    plugin-opts:
      mode: http
      host: mask.example
  - name: plain
    type: socks5
    server: 127.0.0.1
    port: 1080
"#,
    )
    .unwrap();
    assert_eq!(clash_nodes.len(), 1);
    assert_eq!(clash_nodes[0].name, "plain");

    let simple = Subscription {
        sub_type: SubscriptionType::Simple,
        ..Default::default()
    };
    let simple_nodes = parse_subscription_content(
        &simple,
        concat!(
            "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#obfs\n",
            "socks5://127.0.0.1:1080#plain"
        ),
    )
    .unwrap();
    assert_eq!(simple_nodes.len(), 1);
    assert_eq!(simple_nodes[0].name, "plain");
}

#[tokio::test]
async fn configured_subscription_user_agent_reaches_fetch_request() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 256];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let size = stream.read(&mut chunk).await.unwrap();
            assert!(size > 0);
            request.extend_from_slice(&chunk[..size]);
        }
        assert!(String::from_utf8_lossy(&request).lines().any(|line| {
            line.trim_end_matches('\r')
                .eq_ignore_ascii_case("user-agent: provider/2.0")
        }));
        let body = "socks5://127.0.0.1:1080#node";
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
    });
    let config = honk_config::parser::parse_dae_config(&format!(
            "subscription {{\nprovider: {{\nurl: 'http://{address}/sub'\nua: 'provider/2.0'\ninterval: 0\n}}\n}}"
        ))
        .unwrap();

    let nodes = SubscriptionManager::new()
        .unwrap()
        .fetch(&config.subscriptions[0])
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(nodes.len(), 1);
}

#[tokio::test]
async fn subscription_store_loads_pre_default_user_agent_key() {
    fn pre_default_filename(sub: &Subscription) -> String {
        fn add_part(hasher: &mut Sha256, value: &[u8]) {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }

        let mut hasher = Sha256::new();
        add_part(&mut hasher, sub.url.as_bytes());
        add_part(&mut hasher, b"");
        for header in &sub.headers {
            add_part(&mut hasher, header.key.as_bytes());
            add_part(&mut hasher, header.value.as_bytes());
        }
        use base64::Engine as _;
        format!(
            "{}.sub",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        )
    }

    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::open(temp.path().join(SUBSCRIPTION_STORE_DIR)).unwrap();
    let sub = Subscription {
        name: "provider".into(),
        url: "https://example.test/subscription".into(),
        ..Subscription::default()
    };
    let content = "socks5://127.0.0.1:1080#stored";
    let old_path = store.root().join(pre_default_filename(&sub));
    write_store_file(store.root(), &old_path, content.as_bytes()).unwrap();

    let restored = store.load_nodes(&sub).await.unwrap().unwrap();
    assert_eq!(restored[0].name, "stored");

    let mut explicit_empty = sub.clone();
    explicit_empty.user_agent = Some(String::new());
    assert!(store.load_nodes(&explicit_empty).await.unwrap().is_some());
}

#[tokio::test]
async fn subscription_cache_identity_isolates_explicit_default_user_agent() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::open(temp.path().join(SUBSCRIPTION_STORE_DIR)).unwrap();
    let default_sub = Subscription {
        name: "provider".into(),
        url: "https://example.test/subscription".into(),
        ..Subscription::default()
    };
    let mut explicit_default = default_sub.clone();
    explicit_default.user_agent = Some(DEFAULT_SUBSCRIPTION_USER_AGENT.into());

    let mut with_header = default_sub.clone();
    with_header
        .headers
        .push(honk_config::subscription::SubscriptionHeader {
            key: "X-Test".into(),
            value: "1".into(),
        });

    store
        .store_content(&with_header, "socks5://127.0.0.1:1080#header".into())
        .await
        .unwrap();
    assert!(store.load_nodes(&explicit_default).await.unwrap().is_none());
    store
        .store_content(&explicit_default, "socks5://127.0.0.1:1080#explicit".into())
        .await
        .unwrap();
    assert!(store.load_nodes(&default_sub).await.unwrap().is_none());
    assert_eq!(
        store.load_nodes(&with_header).await.unwrap().unwrap()[0].name,
        "header"
    );
    assert_eq!(
        store.load_nodes(&explicit_default).await.unwrap().unwrap()[0].name,
        "explicit"
    );
}

#[tokio::test]
async fn fetch_error_chain_redacts_subscription_url() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const SENTINEL: &str = "subscription-secret-sentinel";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 256];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let size = stream.read(&mut chunk).await.unwrap();
            assert!(size > 0, "HTTP request ended before its headers");
            request.extend_from_slice(&chunk[..size]);
            assert!(request.len() <= 16 * 1024, "HTTP request headers too large");
        }
        let request = String::from_utf8_lossy(&request);
        let expected = format!("user-agent: {DEFAULT_SUBSCRIPTION_USER_AGENT}");
        assert!(
            request
                .lines()
                .any(|line| { line.trim_end_matches('\r').eq_ignore_ascii_case(&expected) })
        );
        stream
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });
    let subscription = Subscription {
        name: "provider".into(),
        url: format!("http://{address}/{SENTINEL}?token={SENTINEL}"),
        ..Subscription::default()
    };

    let error = SubscriptionManager::new()
        .unwrap()
        .fetch(&subscription)
        .await
        .unwrap_err();
    server.await.unwrap();
    let chain = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!chain.contains(SENTINEL));
    assert!(!format!("{error:?}").contains(SENTINEL));
}

#[tokio::test]
async fn subscription_store_recovers_last_valid_fetch() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::open(temp.path().join(SUBSCRIPTION_STORE_DIR)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let valid = "socks5://127.0.0.1:1080#stored";
    let server = tokio::spawn(async move {
        for body in [valid, "not a subscription"] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });

    let mut sub = Subscription {
        name: "provider".into(),
        url: format!("http://{address}/subscription"),
        ..Subscription::default()
    };
    let path = store.path_for(&sub);
    let original_id = sub.id;
    let manager = SubscriptionManager::new().unwrap();
    let fetched = manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].subscription_id, Some(original_id));
    assert!(manager.fetch_and_store(&sub, Some(&store)).await.is_err());
    server.await.unwrap();

    sub.id = uuid::Uuid::new_v4();
    sub.name = "renamed-provider".into();
    assert_eq!(store.path_for(&sub), path);
    let restored = store.load_nodes(&sub).await.unwrap().unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].name, "stored");
    assert_eq!(restored[0].subscription_id, Some(sub.id));

    let directory_mode = fs::metadata(store.root()).unwrap().permissions().mode() & 0o777;
    let file_mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(directory_mode, 0o700);
    assert_eq!(file_mode, 0o600);
    assert_eq!(fs::read_dir(store.root()).unwrap().count(), 1);
}

#[tokio::test]
async fn subscription_store_skips_rejected_legacy_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let preferred = temp.path().join("preferred");
    let old = temp.path().join("old");
    let cwd = temp.path().join("cwd");
    let sub = Subscription {
        url: "https://example.invalid/subscription".into(),
        ..Subscription::default()
    };
    let retained = SubscriptionStore::open(cwd.clone()).unwrap();
    retained
        .store_content(&sub, "socks5://127.0.0.1:1080#retained".into())
        .await
        .unwrap();
    fs::write(&old, "not a directory").unwrap();

    for symlink in [false, true] {
        if symlink {
            fs::remove_file(&old).unwrap();
            let target = temp.path().join("symlink-target");
            fs::create_dir(&target).unwrap();
            std::os::unix::fs::symlink(target, &old).unwrap();
        }
        let store =
            SubscriptionStore::open_with_legacy(preferred.clone(), [old.clone(), cwd.clone()])
                .unwrap();
        let nodes = store.load_nodes(&sub).await.unwrap().unwrap();
        assert_eq!(nodes[0].name, "retained");
        assert!(!preferred.exists());
    }
}

#[test]
fn subscription_store_rejects_foreign_owner_before_chmod() {
    for mode in [0o700, 0o755] {
        assert!(
            store_directory_needs_chmod(1001, 1000, mode, true, false).is_err(),
            "a foreign-owned store must be refused before changing permissions"
        );
    }
    assert!(!store_directory_needs_chmod(1000, 1000, 0o700, true, false).unwrap());
    assert!(store_directory_needs_chmod(1000, 1000, 0o755, true, false).unwrap());
}

#[test]
fn subscription_store_rejects_symlink_directory() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let link = temp.path().join(SUBSCRIPTION_STORE_DIR);
    symlink(target, &link).unwrap();
    assert!(SubscriptionStore::open(link).is_err());
}
fn assert_c17_original_indices(
    sub_type: SubscriptionType,
    fixture: &str,
    expected_indices: &[(usize, honk_config::diagnostic::Severity)],
    expected_codes: &[&str],
) {
    let subscription = Subscription {
        sub_type,
        ..Subscription::default()
    };
    let mut diagnostics = Vec::new();
    let nodes =
        parse_subscription_content_with_diagnostics(&subscription, fixture, &mut diagnostics)
            .unwrap();

    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["usable-proxy"]
    );
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.entry_index, diagnostic.severity))
            .collect::<Vec<_>>(),
        expected_indices
            .iter()
            .map(|&(index, severity)| (Some(index), severity))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>(),
        expected_codes
    );
    let rendered = diagnostics
        .iter()
        .map(|diagnostic| format!("{diagnostic:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!rendered.contains("secret.example"));
    assert!(!rendered.contains("secret-password"));
}

#[test]
fn c17_structured_adapters_retain_original_mixed_entry_indices() {
    use honk_config::diagnostic::Severity;

    assert_c17_original_indices(
        SubscriptionType::Simple,
        include_str!("../../tests/fixtures/c17-mixed-structured.json"),
        &[
            (1, Severity::Info),
            (2, Severity::Warning),
            (3, Severity::Warning),
            (4, Severity::Warning),
        ],
        &[
            "subscription-profile-entry",
            "malformed-subscription-entry",
            "unsupported-subscription-entry",
            "malformed-subscription-entry",
        ],
    );
    assert_c17_original_indices(
        SubscriptionType::Sip008,
        include_str!("../../tests/fixtures/c17-mixed-sip008.json"),
        &[(1, Severity::Warning), (2, Severity::Warning)],
        &[
            "malformed-subscription-entry",
            "malformed-subscription-entry",
        ],
    );
    assert_c17_original_indices(
        SubscriptionType::Clash,
        include_str!("../../tests/fixtures/c17-mixed-clash.json"),
        &[
            (1, Severity::Warning),
            (2, Severity::Warning),
            (3, Severity::Warning),
            (4, Severity::Warning),
        ],
        &[
            "unsupported-subscription-entry",
            "malformed-subscription-entry",
            "unsupported-subscription-entry",
            "malformed-subscription-entry",
        ],
    );
}

#[test]
fn c18_physical_lines_and_decoded_parent_survive() {
    use honk_config::diagnostic::Severity;
    for (body, profile, unsupported) in [
        (include_str!("../../tests/fixtures/c18-uri-lines.txt"), 3, 4),
        (
            include_str!("../../tests/fixtures/c18-record-lines.txt"),
            3,
            6,
        ),
    ] {
        for encoded in [false, true] {
            let content = if encoded {
                base64::engine::general_purpose::STANDARD.encode(body)
            } else {
                body.to_string()
            };
            let mut diagnostics = Vec::new();
            let nodes = parse_subscription_content_with_diagnostics(
                &Subscription::default(),
                &content,
                &mut diagnostics,
            )
            .unwrap();
            assert_eq!(nodes[0].name, "usable");
            assert_eq!(
                diagnostics
                    .iter()
                    .map(|d| (d.line, d.severity))
                    .collect::<Vec<_>>(),
                [
                    (Some(profile), Severity::Info),
                    (Some(unsupported), Severity::Warning)
                ]
            );
            assert_eq!(diagnostics[1].entry_index, Some(unsupported));
            assert_eq!(diagnostics[1].code, "unsupported-subscription-entry");
            let source = &diagnostics[1].source;
            assert_eq!(source.index(), usize::from(encoded));
            assert_eq!(
                source.sources().metadata()[source.index()].parent,
                encoded.then_some(0)
            );
            assert!(diagnostics.iter().all(|d| d.span.is_none()));
        }
    }
}

const C19_PARTIAL: &str = include_str!("../../tests/fixtures/c19-partial-body.txt");
const C19_INVALID: &str = include_str!("../../tests/fixtures/c19-invalid-body.txt");

#[test]
fn c19_body_acceptance_retains_first_usable_and_failure_diagnostics() {
    let sub = Subscription::default();
    let mut diagnostics = Vec::new();
    let nodes =
        parse_subscription_content_with_diagnostics(&sub, C19_PARTIAL, &mut diagnostics).unwrap();
    assert_eq!(
        nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        ["first"]
    );
    assert_eq!(
        diagnostics
            .iter()
            .map(|d| d.entry_index)
            .collect::<Vec<_>>(),
        [Some(1), Some(3)]
    );
    assert_eq!(diagnostics[1].related_indices, [2]);
    let prefix = diagnostics.clone();
    assert!(
        parse_subscription_content_with_diagnostics(&sub, C19_INVALID, &mut diagnostics).is_err()
    );
    assert_eq!(&diagnostics[..prefix.len()], &prefix);
    assert_eq!(
        diagnostics[prefix.len()..]
            .iter()
            .filter(|d| !d.terminal)
            .count(),
        2
    );
    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
}

#[tokio::test]
async fn c19_store_acceptance_is_independent_of_runtime_publication() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub = Subscription {
        url: format!("http://{}/sub", listener.local_addr().unwrap()),
        ..Subscription::default()
    };
    let server = tokio::spawn(async move {
        for body in [C19_PARTIAL, C19_INVALID, C19_PARTIAL] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 2048];
            let mut received = 0;
            while !request[..received]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                assert!(received < request.len(), "HTTP request headers too large");
                let size = stream.read(&mut request[received..]).await.unwrap();
                assert!(size > 0, "HTTP request ended before its headers");
                received += size;
            }
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
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::open(temp.path().join("store")).unwrap();
    let manager = SubscriptionManager::new().unwrap();
    let nodes = manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
    let saved = store.path_for(&sub);
    assert_eq!(fs::read_to_string(&saved).unwrap(), C19_PARTIAL);
    assert!(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[
            nodes[0].clone(),
            nodes[0].clone()
        ])
        .is_err()
    );
    assert_eq!(
        store.load_nodes(&sub).await.unwrap().unwrap()[0].id,
        nodes[0].id
    );
    assert!(manager.fetch_and_store(&sub, Some(&store)).await.is_err());
    assert_eq!(fs::read_to_string(&saved).unwrap(), C19_PARTIAL);
    fs::write(&saved, C19_INVALID).unwrap();
    assert!(store.load_nodes(&sub).await.is_err());
    fs::remove_file(&saved).unwrap();
    fs::remove_dir(store.root()).unwrap();
    fs::write(store.root(), "not a directory").unwrap();
    let mut diagnostics = Vec::new();
    assert_eq!(
        manager
            .fetch_and_store_with_diagnostics(&sub, Some(&store), &mut diagnostics)
            .await
            .unwrap()[0]
            .id,
        nodes[0].id
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "subscription-store-write-failed")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn c19_invalid_http_encoding_preserves_saved_body() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let body = include_bytes!("../../tests/fixtures/c19-invalid-utf8-body.txt");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sub = Subscription {
        url: format!("http://{}/sub", listener.local_addr().unwrap()),
        ..Subscription::default()
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
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::open(temp.path().join("store")).unwrap();
    store.store_content(&sub, C19_PARTIAL.into()).await.unwrap();
    let manager = SubscriptionManager::new().unwrap();
    let mut diagnostics = Vec::new();
    let result = manager
        .fetch_and_store_with_diagnostics(&sub, Some(&store), &mut diagnostics)
        .await;
    server.await.unwrap();
    assert!(
        result.is_err(),
        "invalid HTTP encoding must reject the body"
    );
    assert_eq!(
        fs::read(store.path_for(&sub)).unwrap(),
        C19_PARTIAL.as_bytes()
    );
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "invalid-subscription-encoding");
    assert!(diagnostics[0].terminal);
    let error = result.unwrap_err();
    let error = error.downcast_ref::<DetailedConfigError>().unwrap();
    assert_eq!(error.diagnostic.as_ref(), &diagnostics[0]);
}

#[test]
fn profile_diagnostic_budget_preserves_nodes_and_caller_prefix() {
    let sub = Subscription::default();
    let mut diagnostics = Vec::new();
    parse_subscription_content_with_diagnostics(&sub, "STATUS=prefix", &mut diagnostics)
        .unwrap_err();
    let prefix = diagnostics.clone();
    let body = format!(
        "[General]\n{}[Proxy]\nfirst = socks5, 127.0.0.1, 1080\nsecond = socks5, 127.0.0.1, 1080\n",
        "x\n".repeat(4096),
    );
    let nodes = parse_subscription_content_with_diagnostics(&sub, &body, &mut diagnostics).unwrap();
    assert_eq!(
        nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        ["first"]
    );
    assert_eq!(&diagnostics[..prefix.len()], &prefix);
    let retained = &diagnostics[prefix.len()..];
    assert!(
        retained.len() <= 129,
        "retained {} diagnostics",
        retained.len()
    );
    assert_eq!(retained[0].line, Some(2));
    assert_eq!(
        retained.last().unwrap().code,
        "subscription-diagnostics-truncated"
    );
    assert!(!retained.iter().any(|d| d.terminal));
}

#[test]
fn uri_diagnostic_budget_preserves_late_valid_node() {
    let body = format!(
        "{}socks5://127.0.0.1:1080#survivor\n",
        "unknown://host:1234\n".repeat(256)
    );
    let mut diagnostics = Vec::new();
    let nodes = parse_subscription_content_with_diagnostics(
        &Subscription::default(),
        &body,
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["survivor"]
    );
    assert!(diagnostics.len() <= 129);
    assert_eq!(
        diagnostics.last().unwrap().code,
        "subscription-diagnostics-truncated"
    );
}

#[test]
fn truncated_all_invalid_body_keeps_terminal_failure() {
    let body = "unknown://host:1234\n".repeat(256);
    let mut diagnostics = Vec::new();
    assert!(
        parse_subscription_content_with_diagnostics(
            &Subscription::default(),
            &body,
            &mut diagnostics,
        )
        .is_err()
    );
    assert!(diagnostics.len() <= 130);
    assert_eq!(
        diagnostics
            .iter()
            .filter(|diagnostic| !diagnostic.terminal)
            .count(),
        129
    );
    assert!(diagnostics.last().unwrap().terminal);
}
