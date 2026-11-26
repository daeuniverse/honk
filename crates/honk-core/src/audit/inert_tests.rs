use crate::audit::{DnsAudit, DnsAuditQuery, DnsAuditWorker};
use crate::dns::query::IngressProfile;

#[test]
fn disabled_feature_uses_zero_sized_inert_hooks() {
    assert_eq!(size_of::<DnsAudit>(), 0);
    assert_eq!(size_of::<Option<DnsAuditQuery>>(), 0);
    assert_eq!(size_of::<Option<DnsAuditWorker>>(), 0);
    let (audit, worker) = DnsAuditWorker::start(&Default::default()).unwrap();
    assert!(worker.is_none());
    let client = "192.0.2.8:53000".parse().unwrap();
    assert!(audit.begin(&[], IngressProfile::Tcp, client).is_none());
    assert!(audit.begin_udp(&[], client).is_none());
}

#[test]
fn enabling_without_feature_is_rejected_before_sender_start() {
    let config = honk_config::config::GlobalConfig {
        syslog_dns_enabled: true,
        ..Default::default()
    };
    let error = match DnsAuditWorker::start(&config) {
        Err(error) => error,
        Ok(_) => panic!("uncompiled DNS audit must reject enablement"),
    };
    assert!(error.to_string().contains("dns-syslog"), "{error}");
}
