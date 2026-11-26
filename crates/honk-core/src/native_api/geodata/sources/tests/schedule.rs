use super::*;
use crate::native_api::tests::run_local_schedule_test;

const GAP_CRON: &str = "30 2 8-14 3 */7";
const INVALID_STORED: &str = r#"{"urls":[{"urls":["https://mirror.example/geosite.dat"]},null],"auto_update":{"enabled":true,"cron":"30 2 8-14 3 */7"},"download":{"route":{"route":"direct"}},"verify_checksum":false}"#;

#[test]
fn unavailable_file_and_retained_schedules_leave_storage_unchanged() {
    if run_local_schedule_test(concat!(
        module_path!(),
        "::unavailable_file_and_retained_schedules_leave_storage_unchanged"
    )) {
        return;
    }
    for record in [None, Some(DAILY_INTERVAL)] {
        let directory = tempfile::tempdir().unwrap();
        if let Some(record) = record {
            store_settings(directory.path(), record);
        }
        let before = stored_record(directory.path());
        for enabled in [true, false] {
            let mut file = schedule_file(Some(enabled), Some(GAP_CRON));
            file.checksum = Some(false);
            assert!(matches!(
                Sources::open(
                    db(directory.path()),
                    &settings("https://config.example/geosite.dat"),
                    &file,
                ),
                Err(Error::ScheduleUnavailable)
            ));
            assert_eq!(stored_record(directory.path()), before);
        }
    }
    let directory = tempfile::tempdir().unwrap();
    store_settings(directory.path(), INVALID_STORED);
    assert!(matches!(
        open(db(directory.path()), &settings("")),
        Err(Error::ScheduleUnavailable)
    ));
    assert_eq!(
        stored_record(directory.path()).as_deref(),
        Some(INVALID_STORED)
    );
}

#[test]
fn a_valid_file_schedule_repairs_an_unavailable_stored_schedule() {
    if run_local_schedule_test(concat!(
        module_path!(),
        "::a_valid_file_schedule_repairs_an_unavailable_stored_schedule"
    )) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    store_settings(directory.path(), INVALID_STORED);
    assert!(matches!(
        open(db(directory.path()), &settings("")),
        Err(Error::ScheduleUnavailable)
    ));
    let sources = open_with(directory.path(), &schedule_file(None, Some("0 4 * * *")));
    let repaired = sources.effective();
    assert_eq!(repaired.auto_update.schedule, cron("0 4 * * *"));
    assert!(repaired.auto_update.enabled);
    assert_eq!(repaired.urls[0], ["https://mirror.example/geosite.dat"]);
    assert_eq!(repaired.download, Route::Direct);
    assert!(!repaired.verify_checksum);
    assert!(sources.next_check_at().is_some());
    drop(sources);
    assert_eq!(
        open_with(directory.path(), &schedule_file(None, Some("0 4 * * *"))).effective(),
        repaired
    );
}

#[test]
fn explicit_unavailable_cron_is_refused_while_disabled_records_remain_repairable() {
    if run_local_schedule_test(concat!(
        module_path!(),
        "::explicit_unavailable_cron_is_refused_while_disabled_records_remain_repairable"
    )) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let record = INVALID_STORED.replace("\"enabled\":true", "\"enabled\":false");
    store_settings(directory.path(), &record);
    let sources = open(db(directory.path()), &settings("")).unwrap();
    let before = sources.effective();
    assert!(matches!(
        sources.apply(patch(
            json!({"auto_update": {"enabled": false, "cron": GAP_CRON}})
        )),
        Err(Error::ScheduleUnavailable)
    ));
    assert!(matches!(
        sources.apply(patch(json!({"auto_update": {"enabled": true}}))),
        Err(Error::ScheduleUnavailable)
    ));
    assert_eq!(sources.effective(), before);
    assert_eq!(
        stored_record(directory.path()).as_deref(),
        Some(record.as_str())
    );
    assert_eq!(
        sources
            .apply(patch(json!({"auto_update": {"enabled": false}})))
            .unwrap(),
        before
    );
    let changed = sources
        .apply(patch(json!({"verify_checksum": true})))
        .unwrap();
    assert_eq!(changed.auto_update, before.auto_update);
    assert!(changed.verify_checksum);
}

#[test]
fn unavailable_runtime_schedule_preserves_retries_and_reports_one_warning_per_episode() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing_subscriber::layer::SubscriberExt as _;

    if run_local_schedule_test(concat!(
        module_path!(),
        "::unavailable_runtime_schedule_preserves_retries_and_reports_one_warning_per_episode"
    )) {
        return;
    }
    struct Warnings(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let warnings = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(Warnings(Arc::clone(&warnings)));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    let now = SystemTime::from(utc("2026-11-11 12:00"));
    let checked = now - HOUR;
    let schedule = cron(GAP_CRON);
    assert_eq!(
        due(&schedule, Some(checked), 0, now, &chrono::Local),
        (None, true)
    );
    assert_eq!(
        due(&schedule, Some(checked), 1, now, &chrono::Local),
        (Some(now + STARTUP_DELAY), true)
    );
    assert_eq!(
        due(&schedule, Some(checked), 3, now, &chrono::Local),
        (Some(now + 3 * HOUR), true)
    );
    for checked in [None, Some(now + HOUR)] {
        assert_eq!(
            due(&schedule, checked, 3, now, &chrono::Local),
            (Some(now + STARTUP_DELAY), true)
        );
    }
    // Model a previously admitted plan that no longer has a local occurrence.
    sources.stored.lock().auto_update = Some(StoredAutoUpdate::new(
        AutoUpdate {
            enabled: true,
            schedule,
        },
        false,
    ));
    {
        let mut status = sources.status.lock();
        status.last_checked_at = Some(checked);
        status.last_error = Some("download_failed".into());
    }
    sources.reschedule(now);
    sources.reschedule(now);
    assert_eq!(sources.next_check_at(), None);
    assert_eq!(warnings.load(Ordering::Relaxed), 1);
    {
        let mut status = sources.status.lock();
        status.failures = 3;
    }
    sources.reschedule(now);
    let next = sources.next_check_at().unwrap();
    assert!(
        (now + 3 * HOUR..=now + 3 * HOUR + Duration::from_secs(MAX_JITTER_SECS)).contains(&next)
    );
    {
        let status = sources.status.lock();
        assert!(status.schedule_unavailable);
        assert_eq!(status.failures, 3);
        assert_eq!(status.last_checked_at, Some(checked));
        assert_eq!(status.last_error.as_deref(), Some("download_failed"));
    }
    assert_eq!(warnings.load(Ordering::Relaxed), 1);
    let disabled = sources
        .apply(patch(json!({"auto_update": {"enabled": false}})))
        .unwrap();
    assert_eq!(disabled.auto_update.schedule, cron(GAP_CRON));
    assert!(!disabled.auto_update.enabled);
    assert_eq!(sources.next_check_at(), None);
    assert!(!sources.status.lock().schedule_unavailable);
    sources.stored.lock().auto_update.as_mut().unwrap().enabled = true;
    sources.reschedule(now);
    assert_eq!(warnings.load(Ordering::Relaxed), 2);
    sources
        .apply(patch(json!({"auto_update": {"cron": "0 4 * * *"}})))
        .unwrap();
    assert!(!sources.status.lock().schedule_unavailable);
    assert_eq!(
        sources.status.lock().last_error.as_deref(),
        Some("download_failed")
    );
}

#[tokio::test]
async fn native_startup_rejects_an_unavailable_schedule_instead_of_dropping_the_owner() {
    use crate::control::ControlPlane;
    use crate::native_api::NativeState;

    if run_local_schedule_test(concat!(
        module_path!(),
        "::native_startup_rejects_an_unavailable_schedule_instead_of_dropping_the_owner"
    )) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    config.global.data_dir = directory.path().to_str().unwrap().into();
    config.assets.geodata = schedule_file(Some(true), Some(GAP_CRON));
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.allow_anonymous_loopback = true;
    config.ensure_builtin_nodes();
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let forwarder = resolver.forwarder();
    let mut control = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        crate::routing::Router::new(&[], "direct").unwrap(),
        Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        forwarder,
    )
    .unwrap();
    control
        .init_cache_db(Some(db(directory.path())), None)
        .await;
    let result = NativeState::new(
        &mut control,
        "127.0.0.1:9527".parse().unwrap(),
        SystemTime::now(),
        std::time::Instant::now(),
    )
    .await;
    let error = result.err().expect("startup must refuse the schedule");
    assert!(
        error
            .to_string()
            .contains("geodata cron has no future occurrence")
    );
    assert_eq!(stored_record(directory.path()), None);
}
