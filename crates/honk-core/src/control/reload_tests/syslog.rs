use super::*;
use crate::audit::tests::{
    current_test_profile, install_test_profile, test_profile_event, test_profile_slots,
};

fn custom(config: &mut Config, label: &str) {
    config.global.syslog_dns_json = format!(
        r#"{{"label":"{label}","revision":"${{template_version}}","client":"${{client_ip}}"}}"#
    );
}

#[tokio::test]
async fn dns_audit_template_reload_publishes_only_after_acceptance_and_noop_keeps_it() {
    let cp = test_cp().await;
    let audit = cp.dns_controller.dns_service().audit;
    install_test_profile(&audit);
    let old = current_test_profile(&audit);
    let mut next = cp.config.read().await.as_ref().clone();
    custom(&mut next, "accepted");
    assert!(
        cp.apply_runtime_config(next, Default::default(), &DrainTracker::new())
            .await
            .accepted()
    );
    let accepted = current_test_profile(&audit);
    assert!(!Arc::ptr_eq(&old, &accepted));
    assert_eq!(test_profile_event(&accepted)["label"], "accepted");
    assert_eq!(test_profile_event(&old)["event"], "dns.query");
    let mut invalid = cp.config.read().await.as_ref().clone();
    invalid.global.syslog_dns_json = r#"{"value":"${unknown}"}"#.into();
    assert!(
        !cp.apply_runtime_config(invalid, Default::default(), &DrainTracker::new())
            .await
            .accepted()
    );
    assert!(Arc::ptr_eq(&current_test_profile(&audit), &accepted));
    let same = cp.config.read().await.as_ref().clone();
    assert!(
        cp.apply_runtime_config(same, Default::default(), &DrainTracker::new())
            .await
            .accepted()
    );
    assert!(Arc::ptr_eq(&current_test_profile(&audit), &accepted));
}

#[tokio::test]
async fn dns_audit_template_rejected_backend_publication_releases_candidate_slot() {
    let cp = test_cp().await;
    let audit = cp.dns_controller.dns_service().audit;
    install_test_profile(&audit);
    let old = current_test_profile(&audit);
    let before = test_profile_slots(&audit);
    let mut next = cp.config.read().await.as_ref().clone();
    custom(&mut next, "rejected");
    next.routing.default_outbound = "block".into();
    cp.ebpf
        .write()
        .await
        .inject_routing_fault(RoutingPushPhase::Root, 1)
        .unwrap();
    assert!(
        !cp.apply_runtime_config(next, Default::default(), &DrainTracker::new())
            .await
            .accepted()
    );
    assert!(Arc::ptr_eq(&old, &current_test_profile(&audit)));
    assert_eq!(test_profile_slots(&audit), before);
}

#[tokio::test]
async fn dns_audit_template_committed_degraded_also_uses_new_snapshot() {
    let cp = test_cp_with_nfq(true).await;
    let audit = cp.dns_controller.dns_service().audit;
    install_test_profile(&audit);
    let current = cp.config.read().await.as_ref().clone();
    assert!(
        cp.apply_runtime_config(current, Default::default(), &DrainTracker::new())
            .await
            .accepted()
    );
    let mut next = cp.config.read().await.as_ref().clone();
    custom(&mut next, "degraded");
    next.global.check_tolerance_ms += 1;
    {
        let mut backend = cp.ebpf.write().await;
        backend.clear_datapath_flags_write_log();
        backend.arm_datapath_flags_write_fault(2).unwrap();
    }
    let result = cp
        .apply_runtime_config(next, Default::default(), &DrainTracker::new())
        .await;
    assert!(
        matches!(result, ReloadOutcome::CommittedDegraded { .. }),
        "{result:?}"
    );
    assert_eq!(
        test_profile_event(&current_test_profile(&audit))["label"],
        "degraded"
    );
}
