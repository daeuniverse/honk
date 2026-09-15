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
