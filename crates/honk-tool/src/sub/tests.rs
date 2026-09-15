use super::udp::build_dns_probe_query;
use super::*;

#[test]
fn udp_check_target_prefers_literals_and_defaults_to_dns_port() {
    for (targets, expected) in [
        (vec!["1.2.3.4"], "1.2.3.4:53"),
        (vec!["2001:db8::1"], "[2001:db8::1]:53"),
        (vec!["[2001:db8::1]"], "[2001:db8::1]:53"),
        (vec!["[2001:db8::1]:5353"], "[2001:db8::1]:5353"),
        (vec!["my.dns.invalid", "9.9.9.9"], "9.9.9.9:53"),
    ] {
        let targets = targets.into_iter().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(
            parse_udp_check_target(&targets).unwrap(),
            UdpCheckTarget::Literal(expected.parse().unwrap())
        );
    }
    assert_eq!(
        parse_udp_check_target(&["my.dns.invalid:5353".to_string()]).unwrap(),
        UdpCheckTarget::Host {
            host: "my.dns.invalid".into(),
            port: 5353,
        }
    );
    assert!(parse_udp_check_target(&[]).is_err());
    assert!(parse_udp_check_target(&[String::new()]).is_err());
}

fn silent_dns_resolver(address: SocketAddr) -> DnsResolver {
    let mut config = honk_config::dns::DnsConfig {
        upstream: vec![honk_config::dns::DnsUpstream {
            name: "test".into(),
            address: address.to_string(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }],
        ..Default::default()
    };
    config.routing.fallback = "test".into();
    DnsResolver::new(&config).unwrap()
}

fn direct_node() -> Node {
    honk_config::Config::builtin_direct_node()
}

#[tokio::test]
async fn udp_dns_resolution_timeout_does_not_abort_unrelated_probe() {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let closed_port = tokio::net::TcpSocket::new_v4().unwrap();
    closed_port.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = closed_port.local_addr().unwrap();
    let targets = ProbeTargets {
        host: address.ip().to_string(),
        port: address.port(),
        url: Some(format!("http://{address}/")),
        timeout: Duration::from_millis(40),
        v4: Some(address),
        v6: Some(address),
        udp_dns: UdpCheckTarget::Host {
            host: "dns.test".into(),
            port: 53,
        },
        dns_resolver: Some(Arc::new(silent_dns_resolver(sink.local_addr().unwrap()))),
    };
    let registry = ProxyRegistry::default_resolver().unwrap();
    let outcome = probe_node(&registry, direct_node(), &targets).await;
    assert_eq!(outcome.udp_dns, Some(Err(ProbeFailureKind::Timeout)));
    assert_eq!(outcome.urltest, Some(Err(ProbeFailureKind::Exchange)));
    assert_eq!(outcome.v4, Some(Err(ProbeFailureKind::Exchange)));
}

#[tokio::test]
async fn udp_dns_without_system_resolver_reports_resolve() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let node = direct_node();
    let target = UdpCheckTarget::Host {
        host: "dns.test".into(),
        port: 53,
    };
    assert_eq!(
        probe_udp_dns(&registry, &node, &target, None, Duration::from_millis(40),).await,
        Some(Err(ProbeFailureKind::Resolve))
    );
}

#[tokio::test]
async fn udp_policy_denied_target_skips_dns_resolution() {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = silent_dns_resolver(sink.local_addr().unwrap());
    let target = UdpCheckTarget::Host {
        host: "dns.test".into(),
        port: 443,
    };
    let registry = ProxyRegistry::default_resolver().unwrap();
    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.network = None;
    vless.flow = Some("xtls-rprx-vision".into());
    assert!((registry
        .find(NodeProtocol::VLess)
        .unwrap()
        .descriptor
        .supports_udp)(&node));
    assert_eq!(
        probe_udp_dns(
            &registry,
            &node,
            &target,
            Some(&resolver),
            Duration::from_millis(40),
        )
        .await,
        None
    );
    let mut packet = [0u8; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), sink.recv(&mut packet))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn udp_policy_denied_target_skips_quic_resolution() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.network = None;
    vless.flow = Some("xtls-rprx-vision".into());

    assert_eq!(
        probe_udp_quic(
            &registry,
            &node,
            "must-not-resolve.invalid",
            443,
            Duration::from_millis(40),
        )
        .await,
        None
    );
}

#[test]
fn dns_probe_query_has_full_header_and_google_a_question() {
    let query = build_dns_probe_query(0x1234);
    assert_eq!(&query[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&query[12..], b"\x06google\x03com\x00\x00\x01\x00\x01");
}

fn vless_node() -> Node {
    let mut node = Node {
        name: "vless-test".into(),
        address: "192.0.2.1:443".into(),
        host: "192.0.2.1".into(),
        port: 443,
        outbound: honk_config::node::OutboundConfig::Vless(honk_config::node::VlessConfig {
            uuid: Some("b831381d-6324-4d53-ad4f-8cda48b30811".into()),
            network: Some("tcp".into()),
            tls: honk_config::node::TlsOptions {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

#[test]
fn stdin_subscription_url_rules() {
    assert_eq!(
        parse_subscription_url_from_stdin("  https://example.com/feed?token=value\n").unwrap(),
        "https://example.com/feed?token=value"
    );
    assert_eq!(
        parse_subscription_url_from_stdin("http://127.0.0.1/sub").unwrap(),
        "http://127.0.0.1/sub"
    );
    for invalid in [
        "",
        "   \n",
        "not a URL",
        "ftp://example.com/sub",
        "https:///",
        "https://one.example/sub\nhttps://two.example/sub",
    ] {
        assert_eq!(
            parse_subscription_url_from_stdin(invalid)
                .unwrap_err()
                .to_string(),
            "invalid subscription URL from stdin"
        );
    }
}

#[test]
fn vless_probe_eligibility_precedence_and_reasons() {
    assert_eq!(
        classify_vless_node(&vless_node()),
        ProbeEligibility::Supported
    );

    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.uuid = None;
    vless.tls.reality_short_id = Some("abc".into());
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::InvalidConfig("invalid-uuid")
    );

    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.tls.reality_short_id = Some("abc".into());
    vless.transport.transport = "kcp".into();
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::InvalidConfig("invalid-reality")
    );

    let mut node = vless_node();
    node.vless_mut().unwrap().transport.transport = "kcp".into();
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::ExpectedUnsupported("unsupported-transport")
    );

    let mut node = vless_node();
    node.vless_mut().unwrap().flow = Some("unsupported-flow-value".into());
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::ExpectedUnsupported("unsupported-flow")
    );

    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.tls.enabled = false;
    vless.flow = Some("xtls-rprx-vision".into());
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::InvalidConfig("vision-without-tls")
    );

    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.transport.transport = "ws".into();
    vless.flow = Some("xtls-rprx-vision".into());
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::ExpectedUnsupported("vision-non-tcp")
    );

    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.network = None;
    vless.flow = Some("xtls-rprx-vision-udp443".into());
    node.id = node.derive_id();
    assert_eq!(classify_vless_node(&node), ProbeEligibility::Supported);

    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision-udp443-extra".into());
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::ExpectedUnsupported("unsupported-flow")
    );

    let mut node = vless_node();
    node.name.clear();
    assert_eq!(
        classify_vless_node(&node),
        ProbeEligibility::InvalidConfig("invalid-config")
    );
}

fn timeout_targets(dns_port: u16, port: u16) -> ProbeTargets {
    ProbeTargets {
        host: "target.invalid".into(),
        port,
        url: None,
        timeout: Duration::from_millis(1),
        v4: None,
        v6: None,
        udp_dns: UdpCheckTarget::Literal(SocketAddr::from(([127, 0, 0, 1], dns_port))),
        dns_resolver: None,
    }
}

#[test]
fn vless_udp_is_rendered_as_not_applicable() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let outcome = ProbeOutcome::timed_out(&registry, &vless_node(), &timeout_targets(53, 443));
    assert_eq!(outcome.udp_dns, None);
    assert_eq!(outcome.udp_quic, None);
    let rendered = render_outcome(&outcome);
    assert!(rendered.contains("dns: n/a"));
    assert!(rendered.contains("quic: n/a"));
}

#[test]
fn vless_udp_mode_is_rendered_as_probeable() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let mut node = vless_node();
    node.vless_mut().unwrap().network = None;
    node.vless_mut().unwrap().multiplex = VlessMultiplex::H2 { padding: false };
    let outcome = ProbeOutcome::timed_out(&registry, &node, &timeout_targets(53, 443));
    assert!(matches!(
        outcome.udp_dns,
        Some(Err(ProbeFailureKind::Timeout))
    ));
    assert!(render_outcome(&outcome).contains("dns: FAIL(timeout)"));
}

#[test]
fn timed_out_vision_targets_are_rendered_per_port_policy() {
    let registry = ProxyRegistry::default_resolver().unwrap();
    let mut node = vless_node();
    let vless = node.vless_mut().unwrap();
    vless.network = None;
    vless.flow = Some("xtls-rprx-vision".into());
    let outcome = ProbeOutcome::timed_out(&registry, &node, &timeout_targets(443, 443));
    assert_eq!(outcome.udp_dns, None);
    assert_eq!(outcome.udp_quic, None);
    let rendered = render_outcome(&outcome);
    assert!(rendered.contains("dns: n/a"));
    assert!(rendered.contains("quic: n/a"));

    node.vless_mut().unwrap().flow = Some("xtls-rprx-vision-udp443".into());
    let outcome = ProbeOutcome::timed_out(&registry, &node, &timeout_targets(443, 443));
    assert_eq!(outcome.udp_dns, Some(Err(ProbeFailureKind::Timeout)));
    assert_eq!(outcome.udp_quic, Some(Err(ProbeFailureKind::Timeout)));
}

#[test]
fn rendered_failures_exclude_connection_identifiers() {
    let mut node = vless_node();
    node.host = "sentinel-host.invalid".into();
    node.address = "sentinel-host.invalid:443".into();
    let vless = node.vless_mut().unwrap();
    vless.uuid = Some("sentinel-uuid".into());
    vless.tls.sni = Some("sentinel-sni.invalid".into());
    vless.tls.reality_public_key = Some("sentinel-reality-key".into());
    let outcome = ProbeOutcome::skipped(&node, classify_vless_node(&node));
    let rendered = render_outcome(&outcome);
    for sentinel in [
        "https://sentinel-url.invalid/private?token=secret",
        "sentinel-host.invalid",
        "sentinel-uuid",
        "sentinel-sni.invalid",
        "sentinel-reality-key",
    ] {
        assert!(!rendered.contains(sentinel));
    }

    for (kind, expected) in [
        (ProbeFailureKind::Resolve, "FAIL(resolve)"),
        (ProbeFailureKind::Timeout, "FAIL(timeout)"),
        (ProbeFailureKind::Exchange, "FAIL(exchange)"),
        (ProbeFailureKind::Handler, "FAIL(handler)"),
        (ProbeFailureKind::Admission, "FAIL(admission)"),
    ] {
        assert_eq!(render_probe_result(&Some(Err(kind)), "n/a"), expected);
    }
}
