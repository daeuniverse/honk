use super::*;
use crate::dns::outcome::{
    DnsOutcome, EffectiveExpiry, OutcomeParts, OutcomeStatus, Provenance, ResponseClass,
};

fn capture() -> (DnsAudit, mpsc::Receiver<Entry>) {
    let (sender, receiver) = mpsc::channel(QUEUE_LEN);
    let audit = DnsAudit {
        sender: Some(sender),
        ..Default::default()
    };
    (audit, receiver)
}

fn begin(audit: &DnsAudit) -> DnsAuditQuery {
    audit
        .begin(
            &query(),
            IngressProfile::Tcp,
            "192.0.2.8:53000".parse().unwrap(),
        )
        .unwrap()
}

fn outcome(provenance: Provenance, final_upstream: Option<&str>) -> DnsOutcome {
    let response = crate::dns::response::build_dns_refused(&query());
    DnsOutcome::new(OutcomeParts {
        status: OutcomeStatus::Accepted,
        response_class: ResponseClass::Nodata,
        provenance,
        domain: "audit.example".into(),
        qtype: 1,
        answer_ips: Vec::new(),
        expiry: EffectiveExpiry::do_not_cache(),
        logical_upstream: Some("initial".into()),
        final_upstream: final_upstream.map(Into::into),
        requery_history: vec!["initial".into(), "intermediate".into(), "final".into()],
        reusable: response.clone().into(),
        rendered: response,
        template: None,
        policy_id: None,
    })
}

#[tokio::test(start_paused = true)]
async fn processing_duration_is_monotonic_fractional_and_frozen_before_queuing() {
    let (audit, mut receiver) = capture();
    let mut pending = begin(&audit);
    pending.entry.as_mut().unwrap().started = SystemTime::now() + Duration::from_secs(3600);
    tokio::time::advance(Duration::from_micros(429_064)).await;
    pending.finish(&crate::dns::response::build_dns_refused(&query()), None);
    tokio::time::advance(Duration::from_secs(60)).await;
    let input = receiver.try_recv().unwrap();
    assert!(input.completed < input.started);
    let value = encode(&input, "instance:1").unwrap();
    assert_eq!(value["duration_ms"], 429.064);
    assert!(value["upstream"].is_null());
    tokio::time::advance(Duration::from_secs(3600)).await;
    assert_eq!(encode(&input, "instance:1").unwrap(), value);
}

#[tokio::test(start_paused = true)]
async fn cancellation_keeps_elapsed_processing_time_without_an_upstream() {
    let (audit, mut receiver) = capture();
    let pending = begin(&audit);
    tokio::time::advance(Duration::from_micros(12_345)).await;
    drop(pending);
    tokio::time::advance(Duration::from_secs(30)).await;
    let input = receiver.try_recv().unwrap();
    let value = encode(&input, "instance:1").unwrap();
    assert_eq!(value["duration_ms"], 12.345);
    assert_eq!(value["result"], "cancelled");
    assert!(value["upstream"].is_null());
}

#[test]
fn upstream_uses_only_the_final_name_and_cache_overrides_retained_metadata() {
    let (audit, mut receiver) = capture();
    for (provenance, final_name, expected) in [
        (Provenance::Upstream, Some("final"), json!("final")),
        (Provenance::Cache, None, json!("cache")),
        (Provenance::Cache, Some("old-upstream"), json!("cache")),
        (Provenance::Stale, Some("failed-upstream"), json!("cache")),
        (Provenance::Fresh, None, json!(null)),
        (Provenance::Upstream, None, json!(null)),
    ] {
        let result = outcome(provenance, final_name);
        begin(&audit).finish(result.rendered(), Some(&result));
        let input = receiver.try_recv().unwrap();
        assert_eq!(encode(&input, "instance:1").unwrap()["upstream"], expected);
    }
}

#[test]
fn upstream_bytes_share_response_admission_and_release_their_permits() {
    let (audit, mut receiver) = capture();
    let result = outcome(Provenance::Upstream, Some("final"));
    let pending = begin(&audit);
    let available = audit.admission.bytes.available_permits();
    let held = Arc::clone(&audit.admission.bytes)
        .try_acquire_many_owned((available - result.rendered().len()) as u32)
        .unwrap();
    pending.finish(result.rendered(), Some(&result));
    assert!(receiver.try_recv().is_err());
    assert_eq!(audit.admission.counters.dropped.load(Ordering::Relaxed), 1);
    drop(held);
    assert_eq!(audit.admission.bytes.available_permits(), QUEUE_BYTES);

    begin(&audit).finish(result.rendered(), Some(&result));
    let input = receiver.try_recv().unwrap();
    assert_eq!(
        audit.admission.bytes.available_permits(),
        QUEUE_BYTES - query().len() - size_of::<Entry>() - result.rendered().len() - "final".len()
    );
    drop(input);
    assert_eq!(audit.admission.bytes.available_permits(), QUEUE_BYTES);
}

#[test]
fn default_event_adds_only_duration_and_upstream_to_the_existing_contract() {
    let input = entry(crate::dns::response::build_dns_refused(&query()));
    let mut value = encode(&input, "instance:1").unwrap();
    assert_eq!(
        value.as_object_mut().unwrap().remove("duration_ms"),
        Some(json!(10.0))
    );
    assert_eq!(
        value.as_object_mut().unwrap().remove("upstream"),
        Some(json!(null))
    );
    assert_eq!(
        value,
        json!({
            "schema_version":1,"event":"dns.query","event_id":"instance:1",
            "message":"DNS 192.0.2.8 audit.example. A IN: REFUSED answers=0",
            "query_time":"1970-01-01T00:00:00.000000Z",
            "completed_at":"1970-01-01T00:00:00.010000Z",
            "client_ip":"192.0.2.8","client_port":53000,"transport":"tcp",
            "domain":"audit.example.","qtype":"A","qclass":"IN",
            "result":"response","rcode":"REFUSED","response_truncated":false,
            "answers":[],"answer_ips":[],"answer_cnames":[],"answer_types":[]
        })
    );
}
