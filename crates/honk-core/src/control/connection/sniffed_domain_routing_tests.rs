use super::*;

fn handoff(outbound: u8, must: u8) -> HandoffResult {
    HandoffResult {
        outbound,
        must,
        mark: 0,
        decision_token: 0,
        dscp: 0,
        mac: [0; 6],
        pname: [0; 16],
        pid: 0,
    }
}

#[test]
fn udp_direct_mark_preserves_rule_and_clears_override() {
    assert_eq!(final_udp_rule_mark(true, "direct", 0x1234), 0x1234);
    assert_eq!(final_udp_rule_mark(false, "direct", 0x1234), 0);
    assert_eq!(final_udp_rule_mark(false, "proxy", 0x1234), 0x1234);
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
