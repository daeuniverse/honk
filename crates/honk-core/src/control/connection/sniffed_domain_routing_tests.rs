use super::*;

fn handoff(outbound: u8, must: u8) -> HandoffResult {
    HandoffResult {
        outbound,
        must,
        mark: 0,
        decision_token: 0,
        routing_generation: 0,
        dscp: 0,
        mac: [0; 6],
        pname: [0; 16],
        pid: 0,
        #[cfg(feature = "native-api")]
        trace_id: 0,
        #[cfg(feature = "native-api")]
        capture: None,
        #[cfg(feature = "native-api")]
        capture_gap: Some("not_instrumented"),
    }
}

#[test]
fn direct_mark_preserves_rule_and_clears_override() {
    for mark in [None, Some(0), Some(0x1234), Some(u32::MAX)] {
        for (routed, replacement, final_outbound, expected) in [
            ("direct", None, "direct", mark),
            ("direct", Some("direct"), "direct", mark),
            ("proxy", Some("direct"), "direct", None),
            ("direct", Some("proxy"), "proxy", None),
            ("proxy", None, "proxy", None),
        ] {
            let mut decision = RoutingDecision {
                outbound: routed.to_owned(),
                must: false,
                mark,
                matched_rule: None,
                reroute_by_sniffed_domain: false,
                #[cfg(feature = "native-api")]
                native_route: None,
            };
            decision.apply_final_outbound(replacement.map(str::to_owned));
            assert_eq!(decision.outbound, final_outbound);
            assert_eq!(decision.mark, expected);
        }
    }
}

#[test]
fn canonical_route_marks_reach_the_legacy_socket_boundary_losslessly() {
    let input = build_connection_info(
        None,
        "198.51.100.1:443".parse().unwrap(),
        "192.0.2.1:53000".parse().unwrap(),
        "tcp",
        None,
    );
    for mark in [None, Some(0), Some(0x1234), Some(u32::MAX)] {
        let mut config = honk_config::routing::RoutingConfig::default();
        config.default_outbound = "direct".into();
        config.default_mark = mark;
        let router = crate::routing::Router::from_config(&config).unwrap();
        let mut decision = RoutingDecision::from_router(
            &router,
            &input,
            None,
            #[cfg(feature = "native-api")]
            None,
        );
        decision.apply_final_outbound(None);
        assert_eq!(decision.mark, mark);
        if mark == Some(0) {
            assert!(
                decision
                    .mark
                    .and_then(honk_outbound::proxy::DirectMark::new)
                    .is_none()
            );
        }
    }
}

#[test]
fn udp_domain_modes_select_routing_identity() {
    assert!(ControlPlaneHandle::should_route_with_sniffed_domain(
        DialMode::Domain,
        Some("www.youtube.com"),
        true,
    ));
    assert!(!ControlPlaneHandle::should_route_with_sniffed_domain(
        DialMode::Domain,
        Some("www.youtube.com"),
        false,
    ));
    assert!(!ControlPlaneHandle::should_route_with_sniffed_domain(
        DialMode::DomainPlus,
        Some("www.youtube.com"),
        true,
    ));
    assert!(ControlPlaneHandle::should_route_with_sniffed_domain(
        DialMode::DomainPlusPlus,
        Some("www.youtube.com"),
        false,
    ));
}

#[test]
fn udp_domain_modes_reroute_only_eligible_handoffs() {
    let group = handoff(OutboundIndex::UserBase as u8, 0);
    assert!(ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::Domain,
        Some("www.youtube.com"),
        true,
        Some(&group),
    ));
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::Domain,
        Some("www.youtube.com"),
        false,
        Some(&group),
    ));
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::DomainPlus,
        Some("www.youtube.com"),
        true,
        Some(&group),
    ));
    assert!(ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::DomainPlusPlus,
        Some("www.youtube.com"),
        false,
        Some(&group),
    ));
}

#[test]
fn udp_domain_reroute_preserves_reserved_and_final_decisions() {
    for outbound in [
        OutboundIndex::Direct as u8,
        OutboundIndex::Block as u8,
        OutboundIndex::MustRules as u8,
        OutboundIndex::ControlPlaneRouting as u8,
    ] {
        assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
            DialMode::DomainPlusPlus,
            Some("www.youtube.com"),
            false,
            Some(&handoff(outbound, 0)),
        ));
    }
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::DomainPlusPlus,
        Some("www.youtube.com"),
        false,
        Some(&handoff(OutboundIndex::UserBase as u8, 1)),
    ));
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::DomainPlusPlus,
        None,
        false,
        Some(&handoff(OutboundIndex::UserBase as u8, 0)),
    ));
}

#[tokio::test]
async fn handoff_process_fields_decode_and_fail_closed() {
    let mut ho = handoff(OutboundIndex::UserBase as u8, 0);
    assert_eq!(ho.process_name(), None, "zeroed pname means no process");
    assert_eq!(ho.process_path().await, None, "pid 0 means no process");

    ho.pname[..4].copy_from_slice(b"curl");
    assert_eq!(ho.process_name().as_deref(), Some("curl"));

    ho.pid = std::process::id();
    assert!(ho.process_path().await.is_some());
    // A dead/invalid pid just omits the path instead of erroring.
    ho.pid = u32::MAX;
    assert_eq!(ho.process_path().await, None);
}

#[test]
fn packet_process_facts_preserve_routing_before_and_after_sniff() {
    use honk_ebpf_common::host::{HOST_PROCESS_PRESENT, HostSourceFacts};
    let packet_process_name =
        |facts: &HostSourceFacts| crate::control::netstack::ProcessMeta::from_facts(facts).name();

    let config = honk_config::parser::parse_dae_config(
        "routing { pname(curl) -> direct\n fallback: block }",
    )
    .unwrap();
    let router = crate::routing::Router::from_config(&config.routing).unwrap();
    let mut facts = HostSourceFacts::default();
    facts.pname[..6].copy_from_slice(b" curl ");
    facts.skb_mark = 0x1234;
    let mut handoff = handoff(OutboundIndex::UserBase as u8, 0);
    handoff.pname = facts.pname;
    assert_eq!(packet_process_name(&facts), None);
    facts.flags |= HOST_PROCESS_PRESENT;
    assert_eq!(packet_process_name(&facts), handoff.process_name());
    for protocol in ["tcp", "udp"] {
        for domain in [None, Some("example.com".to_owned())] {
            let mut input = build_connection_info(
                domain,
                "198.51.100.1:443".parse().unwrap(),
                "192.0.2.1:53000".parse().unwrap(),
                protocol,
                None,
            );
            input.process_name = packet_process_name(&facts);
            input.dscp = Some(12);
            let decision = RoutingDecision::from_router(
                &router,
                &input,
                None,
                #[cfg(feature = "native-api")]
                None,
            );
            assert_eq!(decision.outbound, "direct");
            assert!(
                decision.mark.is_none(),
                "captured mark is not an output action"
            );
            assert!(input.mac.is_none());
        }
    }
    facts.pname.fill(b' ');
    assert_eq!(packet_process_name(&facts), None);
}
