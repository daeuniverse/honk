use super::*;
use base64::Engine as _;
use honk_config::types::NodeProtocol;

mod clash;

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
fn subscription_store_rejects_symlink_directory() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let link = temp.path().join(SUBSCRIPTION_STORE_DIR);
    symlink(target, &link).unwrap();
    assert!(SubscriptionStore::open(link).is_err());
}
