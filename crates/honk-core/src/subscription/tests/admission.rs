use super::*;

#[test]
fn uri_rejections_keep_safe_reason_fields_during_admission() {
    let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@private.example:443?pbk=PRIVATE_KEY";
    let invalid = format!(
        "{uri}&packet-encoding=PRIVATE_VALUE#PRIVATE_NAME\n{uri}&mux=xray&concurrency=PRIVATE_VALUE\n{uri}&flow=xtls-rprx-vision&mux=h2mux\n{uri}&vless_mode=PRIVATE_VALUE\n"
    );
    for with_neighbor in [true, false] {
        let body = if with_neighbor {
            format!("{invalid}socks5://127.0.0.1:1080#neighbor\n")
        } else {
            invalid.clone()
        };
        let mut diagnostics = Vec::new();
        let result = parse_subscription_content_with_diagnostics(
            &Subscription::default(),
            &body,
            &mut diagnostics,
        );
        if with_neighbor {
            let nodes = result.unwrap();
            assert_eq!(
                nodes
                    .iter()
                    .map(|node| node.name.as_str())
                    .collect::<Vec<_>>(),
                ["neighbor"]
            );
            assert_eq!(diagnostics.len(), 4);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.diagnostic.code, "empty-subscription-body");
            assert_eq!(diagnostics.len(), 5);
            assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
        }
        for (index, field) in ["packet_encoding", "multiplex.tcp", "flow", "vless_mode"]
            .into_iter()
            .enumerate()
        {
            let diagnostic = &diagnostics[index];
            let ordinal = index + 1;
            assert_eq!(diagnostic.code, "malformed-subscription-entry");
            assert_eq!(
                diagnostic.setting.to_string(),
                format!("entries[{ordinal}].{field}")
            );
            assert_eq!(diagnostic.line, Some(ordinal));
            assert_eq!(diagnostic.entry_index, Some(ordinal));
            assert_eq!(diagnostic.severity, Severity::Warning);
            assert!(!diagnostic.terminal);
            assert_eq!(diagnostic.value, SafeValue::Redacted);
            assert!(diagnostic.source.same_source(&diagnostics[0].source));
            let rendered = format!("{diagnostic:?} {:?}", diagnostic.to_legacy());
            for secret in [
                "PRIVATE_",
                "private.example",
                "b831381d-6324-4d53-ad4f-8cda48b30811",
            ] {
                assert!(!rendered.contains(secret));
            }
        }
    }
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
        include_str!("../../../tests/fixtures/c17-mixed-structured.json"),
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
        include_str!("../../../tests/fixtures/c17-mixed-sip008.json"),
        &[(1, Severity::Warning), (2, Severity::Warning)],
        &[
            "malformed-subscription-entry",
            "malformed-subscription-entry",
        ],
    );
    assert_c17_original_indices(
        SubscriptionType::Clash,
        include_str!("../../../tests/fixtures/c17-mixed-clash.json"),
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
        (
            include_str!("../../../tests/fixtures/c18-uri-lines.txt"),
            3,
            4,
        ),
        (
            include_str!("../../../tests/fixtures/c18-record-lines.txt"),
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

#[test]
fn xhttp_mihomo_options_reach_canonical_nodes_and_identity() {
    let body = r#"proxies:
  - {name: first, type: vless, server: example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: splithttp, alpn: [' h2 ', '', ' '], xhttp-opts: {path: api, host: front.example, mode: stream-up, headers: {X-B: b, x-a: a}, x-padding-bytes: 123-456, no-grpc-header: true, sc-max-each-post-bytes: 4096, sc-min-posts-interval-ms: 0-50}}
  - {name: alias, type: vless, server: example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: xhttp, xhttp-opts: {path: /api/, host: front.example, mode: stream-up, headers: {X-A: a, x-b: b}, x-padding-bytes: {min: 123, max: 456}, no-grpc-header: true, sc-max-each-post-bytes: '4096', sc-min-posts-interval-ms: {min: 0, max: 50}}}
  - {name: changed, type: vless, server: example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: xhttp, xhttp-opts: {path: /changed}}
"#;
    let mut diagnostics = Vec::new();
    let nodes = parse_subscription_content_with_diagnostics(
        &Subscription::default(),
        body,
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(
        nodes.len(),
        2,
        "equal aliases deduplicate; changed path survives"
    );
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].code, "duplicate-subscription-entry");
    let options = nodes[0].transport().unwrap().xhttp.as_ref().unwrap();
    assert_eq!(options.path, "/api/");
    assert_eq!(options.host.as_deref(), Some("front.example"));
    assert_eq!(options.mode, honk_config::node::XhttpMode::StreamUp);
    assert_eq!(options.headers.get("x-a").map(String::as_str), Some("a"));
    assert_eq!(
        options.x_padding_bytes,
        honk_config::node::XhttpRange { min: 123, max: 456 }
    );
    assert!(options.no_grpc_header);
    assert_eq!(options.sc_max_each_post_bytes.max, 4096);
    assert_eq!(
        options.sc_min_posts_interval_ms,
        honk_config::node::XhttpRange { min: 0, max: 50 }
    );
    assert_eq!(nodes[0].tls().unwrap().alpn, ["h2"]);
    assert_ne!(nodes[0].id, nodes[1].id);
}

#[test]
fn xhttp_unsupported_raw_presence_salvages_siblings_and_redacts_errors() {
    for field in [
        "download-settings",
        "reuse-settings",
        "session-placement",
        "seq-placement",
        "uplink-data-placement",
        "uplink-http-method",
        "x-padding-obfs-mode",
        "PRIVATE_UNKNOWN",
    ] {
        for value in ["null", "''", "{}", "false"] {
            let body = format!(
                "proxies:\n  - {{name: PRIVATE_NAME, type: vless, server: private.example, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, xhttp-opts: {{{field}: {value}}}}}\n  - {{name: survivor, type: socks5, server: 127.0.0.1, port: 1080}}\n"
            );
            let mut diagnostics = Vec::new();
            let nodes = parse_subscription_content_with_diagnostics(
                &Subscription::default(),
                &body,
                &mut diagnostics,
            )
            .unwrap();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].name, "survivor");
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].entry_index, Some(1));
            let rendered = format!("{diagnostics:?}");
            assert!(!rendered.contains("PRIVATE_"));
            assert!(!rendered.contains("private.example"));
            assert!(!rendered.contains("b831381d-6324-4d53-ad4f-8cda48b30811"));
        }
    }
    for options in [
        "null",
        "{headers: {Connection: close}}",
        "{x-padding-bytes: '0'}",
        "{mode: unsupported}",
    ] {
        let body = format!(
            "proxies: [{{name: invalid, type: vless, server: example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, xhttp-opts: {options}}}]"
        );
        assert!(parse_subscription_content(&Subscription::default(), &body).is_err());
    }
    for alpn in ["[http/1.1]", "[h3]", "[h2, http/1.1]"] {
        let body = format!(
            "proxies: [{{name: invalid, type: vless, server: example.com, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, alpn: {alpn}}}]"
        );
        assert!(parse_subscription_content(&Subscription::default(), &body).is_err());
    }
}

#[test]
fn official_sing_box_and_records_explicitly_reject_xhttp_with_salvage() {
    for transport in ["xhttp", "splithttp"] {
        let body = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"invalid","server":"example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","transport":{{"type":"{transport}"}}}},{{"type":"socks","tag":"survivor","server":"127.0.0.1","server_port":1080}}]}}"#
        );
        let mut diagnostics = Vec::new();
        let nodes = parse_subscription_content_with_diagnostics(
            &Subscription::default(),
            &body,
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "survivor");
        assert_eq!(diagnostics.len(), 1);
        for claim in [
            format!("transport={transport}"),
            format!("{transport}=false"),
            format!("{transport}-opts="),
            transport.to_string(),
        ] {
            let body = format!(
                "invalid=trojan,example.com,443,password=secret,{claim}\nsurvivor=socks5,127.0.0.1,1080\n"
            );
            let mut diagnostics = Vec::new();
            let nodes = parse_subscription_content_with_diagnostics(
                &Subscription::default(),
                &body,
                &mut diagnostics,
            )
            .unwrap();
            assert_eq!(nodes.len(), 1, "{claim}");
            assert_eq!(nodes[0].name, "survivor", "{claim}");
            assert_eq!(diagnostics.len(), 1, "{claim}");
        }
    }
}

#[test]
fn vmess_xhttp_tls_and_plain_entries_survive_subscription_dedup() {
    let mut fixture = serde_json::json!({"ps":"posture","add":"example.com","port":443,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"xhttp"});
    let plain = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(fixture.to_string())
    );
    fixture["tls"] = serde_json::json!("tls");
    let tls = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(fixture.to_string())
    );
    let mut diagnostics = Vec::new();
    let nodes = parse_subscription_content_with_diagnostics(
        &Subscription::default(),
        &format!("{plain}\n{tls}\n"),
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(nodes.len(), 2);
    assert!(diagnostics.is_empty());
    assert_ne!(nodes[0].id, nodes[1].id);
    assert_ne!(
        nodes[0].tls().unwrap().enabled,
        nodes[1].tls().unwrap().enabled
    );
}
