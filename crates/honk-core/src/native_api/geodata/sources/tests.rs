use super::*;

const SECOND: Duration = Duration::from_secs(1);
const HOUR: Duration = Duration::from_secs(3600);

fn db(directory: &std::path::Path) -> Arc<StateDb> {
    Arc::new(StateDb::open_for_test(directory, 28672))
}

/// Opens with no `assets.geodata` schedule or checksum keys in the file.
fn open(db: Arc<StateDb>, settings: &NativeApiConfig) -> rusqlite::Result<Sources> {
    Sources::open(db, settings, &GeodataDefaults::default())
}

fn settings(geosite: &str) -> NativeApiConfig {
    NativeApiConfig {
        geosite_download_url: geosite.into(),
        ..Default::default()
    }
}

fn invalid() -> ApiError {
    crate::native_api::config::invalid()
}

fn patch(value: Value) -> Option<Patch> {
    Patch::parse(value, invalid).expect("valid patch")
}

#[test]
fn the_file_seeds_the_stored_urls_at_startup_over_a_patch() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    sources
        .apply(patch(
            json!({"geosite": {"urls": ["https://patched.example/geosite.dat"]},
            "geoip": {"urls": ["https://patched.example/geoip.dat"]}}),
        ))
        .unwrap();
    assert_eq!(sources.effective().source, Source::Override);
    drop(sources);
    let sources = open(
        db(directory.path()),
        &settings("https://config.example/geosite.dat"),
    )
    .unwrap();
    let seeded = sources.effective();
    assert_eq!(seeded.source, Source::Override);
    assert_eq!(
        seeded.urls,
        [
            vec!["https://config.example/geosite.dat".to_owned()],
            vec!["https://patched.example/geoip.dat".to_owned()],
        ]
    );
    let patched = sources
        .apply(patch(
            json!({"geosite": {"urls": ["https://patched.example/geosite.dat"]}}),
        ))
        .unwrap();
    assert_eq!(patched.source, Source::Override);
    assert_eq!(patched.urls[0], ["https://patched.example/geosite.dat"]);
    let auto = sources
        .apply(patch(json!({"auto_update": {"enabled": true}})))
        .unwrap();
    assert_eq!(auto.source, Source::Override);
    assert!(auto.auto_update.enabled);
}

#[test]
fn a_changed_file_url_is_seeded_at_the_next_startup() {
    let directory = tempfile::tempdir().unwrap();
    let first = open(
        db(directory.path()),
        &settings("https://first.example/geosite.dat"),
    )
    .unwrap();
    first
        .apply(patch(
            json!({"auto_update": {"enabled": true, "interval_hours": 48}}),
        ))
        .unwrap();
    drop(first);
    let second = open(
        db(directory.path()),
        &settings("https://second.example/geosite.dat"),
    )
    .unwrap();
    let seeded = second.effective();
    assert_eq!(seeded.source, Source::Config);
    assert_eq!(seeded.urls[0], ["https://second.example/geosite.dat"]);
    assert_eq!(seeded.urls[1], DEFAULT_URLS[1].map(str::to_owned).to_vec());
    assert_eq!(
        seeded.auto_update,
        AutoUpdate {
            enabled: true,
            schedule: Schedule::Interval(48)
        }
    );
}

#[test]
fn a_one_asset_patch_leaves_the_other_list_to_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let file = NativeApiConfig {
        geoip_download_url: "https://config.example/geoip.dat".into(),
        ..Default::default()
    };
    let sources = open(db(directory.path()), &file).unwrap();
    sources
        .apply(patch(
            json!({"geosite": {"urls": ["https://patched.example/geosite.dat"]}}),
        ))
        .unwrap();
    drop(sources);
    let reopened = open(db(directory.path()), &settings(""))
        .unwrap()
        .effective();
    assert_eq!(reopened.urls[0], ["https://patched.example/geosite.dat"]);
    assert_eq!(
        reopened.urls[1],
        DEFAULT_URLS[1].map(str::to_owned).to_vec()
    );
}

#[test]
fn a_url_patch_is_stored_and_null_deletes_everything() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    assert_eq!(sources.effective().source, Source::Default);
    let stored = sources
        .apply(patch(
            json!({"geosite": {"urls": ["https://mirror.example/geosite.dat"]},
            "auto_update": {"interval_hours": 48}}),
        ))
        .unwrap();
    assert_eq!(stored.source, Source::Override);
    assert_eq!(stored.urls[1], DEFAULT_URLS[1].map(str::to_owned).to_vec());
    assert_eq!(stored.auto_update.schedule, Schedule::Interval(48));
    drop(sources);
    let sources = open(db(directory.path()), &settings("")).unwrap();
    assert_eq!(sources.effective().urls, stored.urls);
    let reset = sources.apply(None).unwrap();
    assert_eq!(reset.source, Source::Default);
    assert_eq!(reset.auto_update, AutoUpdate::default());
    drop(sources);
    let rows: i64 = db(directory.path())
        .strict()
        .query_row("SELECT count(*) FROM geodata_settings", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn patches_outside_the_url_and_interval_rules_are_refused() {
    let long = format!("https://mirror.example/{}", "a".repeat(4096));
    for value in [
        json!({}),
        json!({"geosite": {"urls": []}}),
        json!({"geosite": {"urls": ["https://a.example/1", "https://a.example/2",
            "https://a.example/3", "https://a.example/4", "https://a.example/5"]}}),
        json!({"geosite": {"urls": ["https://a.example/1", "https://a.example/1"]}}),
        json!({"geosite": {"urls": ["ftp://a.example/geosite.dat"]}}),
        json!({"geosite": {"urls": ["https://user@a.example/geosite.dat"]}}),
        json!({"geosite": {"urls": ["https://a.example/geosite.dat#top"]}}),
        json!({"geosite": {"urls": [long]}}),
        json!({"geosite": null}),
        json!({"auto_update": {}}),
        json!({"auto_update": {"interval_hours": 5}}),
        json!({"auto_update": {"interval_hours": 169}}),
        json!({"source": "override"}),
    ] {
        assert!(Patch::parse(value.clone(), invalid).is_err(), "{value}");
    }
}

#[test]
fn automatic_updates_are_on_by_default() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    assert!(sources.effective().auto_update.enabled);
}

#[test]
fn the_default_schedule_is_daily_at_three() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    let effective = sources.effective();
    assert_eq!(
        effective.auto_update.schedule,
        Schedule::Cron(Cron::parse("0 3 * * *").unwrap())
    );
    assert_eq!(
        effective.json(str::to_owned, |_| None)["auto_update"],
        json!({"enabled": true, "interval_hours": 24, "cron": "0 3 * * *"})
    );
}

/// Stores `record` as the settings row, as an earlier version wrote it.
fn store_settings(directory: &std::path::Path, record: &str) {
    db(directory)
        .strict()
        .execute(
            "INSERT INTO geodata_settings (id, record) VALUES (1, ?1)",
            [record],
        )
        .unwrap();
}

const DAILY_INTERVAL: &str =
    r#"{"urls":[null,null],"auto_update":{"enabled":true,"interval_hours":24}}"#;

fn unix(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Stores `value`, an SQL expression, as the status row.
fn store_status(directory: &std::path::Path, value: &str) {
    db(directory)
        .strict()
        .execute(
            &format!("INSERT INTO geodata_status (id, record) VALUES (1, {value})"),
            [],
        )
        .unwrap();
}

fn stored_status(directory: &std::path::Path) -> Option<String> {
    db(directory)
        .strict()
        .query_row(
            "SELECT record FROM geodata_status WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

/// Opens with the last check `ago` before now and returns the scheduled
/// check with the times just before and after the open.
fn reopened_after(ago: Duration) -> (SystemTime, SystemTime, SystemTime, SystemTime) {
    let directory = tempfile::tempdir().unwrap();
    store_settings(directory.path(), DAILY_INTERVAL);
    let checked = SystemTime::UNIX_EPOCH + Duration::from_secs(unix(SystemTime::now())) - ago;
    store_status(
        directory.path(),
        &format!("'{{\"last_checked_at\":{}}}'", unix(checked)),
    );
    let before = SystemTime::now();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    let after = SystemTime::now();
    let next = sources.next_check_at().expect("a check is scheduled");
    (checked, before, after, next)
}

#[test]
fn a_first_startup_waits_only_the_startup_delay() {
    let directory = tempfile::tempdir().unwrap();
    let before = SystemTime::now();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    let after = SystemTime::now();
    let next = sources.next_check_at().expect("a check is scheduled");
    assert!(next >= before + STARTUP_DELAY, "{next:?}");
    assert!(next <= after + STARTUP_DELAY + HOUR, "{next:?}");
}

#[test]
fn the_update_status_survives_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    store_settings(directory.path(), DAILY_INTERVAL);
    let sources = open(db(directory.path()), &settings("")).unwrap();
    sources.record(Ok((Vec::new(), true)));
    sources.record(Err("download_failed".into()));
    let (checked, updated) = {
        let status = sources.status.lock();
        (
            status.last_checked_at.unwrap(),
            status.last_updated_at.unwrap(),
        )
    };
    drop(sources);
    let reopened = open(db(directory.path()), &settings("")).unwrap();
    let status = reopened.status.lock();
    assert_eq!(status.last_checked_at.map(unix), Some(unix(checked)));
    assert_eq!(status.last_updated_at.map(unix), Some(unix(updated)));
    assert_eq!(status.last_error.as_deref(), Some("download_failed"));
    assert_eq!(status.failures, 1);
    // One failure: the backoff of an hour, not the interval, still applies.
    let wait = status
        .next_check_at
        .unwrap()
        .duration_since(status.last_checked_at.unwrap())
        .unwrap();
    assert!(wait >= HOUR && wait <= 2 * HOUR, "{wait:?}");
}

#[test]
fn a_restart_after_a_missed_check_waits_only_the_startup_delay() {
    let (_, before, after, next) = reopened_after(48 * HOUR);
    assert!(next >= before + STARTUP_DELAY, "{next:?}");
    assert!(next <= after + STARTUP_DELAY + HOUR, "{next:?}");
}

#[test]
fn a_restart_after_a_recent_check_waits_out_the_interval() {
    let (checked, _, _, next) = reopened_after(2 * HOUR);
    assert!(next >= checked + 24 * HOUR, "{next:?}");
    assert!(next <= checked + 25 * HOUR, "{next:?}");
}

// A clock that ran ahead and was corrected leaves a last check in the future.
// Every restart treats it as due, so a host that restarts more often than the
// interval still checks, and that check replaces the bad time.
#[test]
fn a_check_recorded_in_the_future_is_due_after_every_restart() {
    let directory = tempfile::tempdir().unwrap();
    store_settings(directory.path(), DAILY_INTERVAL);
    let future = unix(SystemTime::now() + 30 * 24 * HOUR);
    store_status(
        directory.path(),
        &format!("'{{\"last_checked_at\":{future}}}'"),
    );
    for _ in 0..3 {
        let before = SystemTime::now();
        let sources = open(db(directory.path()), &settings("")).unwrap();
        let after = SystemTime::now();
        let next = sources.next_check_at().expect("a check is scheduled");
        assert!(next >= before + STARTUP_DELAY, "{next:?}");
        assert!(next <= after + STARTUP_DELAY + HOUR, "{next:?}");
    }
    let sources = open(db(directory.path()), &settings("")).unwrap();
    sources.record(Ok((Vec::new(), false)));
    let checked = sources.status.lock().last_checked_at.unwrap();
    drop(sources);
    let reopened = open(db(directory.path()), &settings("")).unwrap();
    let next = reopened.next_check_at().expect("a check is scheduled");
    let checked = SystemTime::UNIX_EPOCH + Duration::from_secs(unix(checked));
    assert!(next >= checked + 24 * HOUR, "{next:?}");
    assert!(next <= checked + 25 * HOUR, "{next:?}");
}

#[test]
fn an_unreadable_update_status_is_ignored_and_replaced() {
    for value in ["'not json'", "x'ff'", r#"'{"failures":-1}'"#] {
        let directory = tempfile::tempdir().unwrap();
        store_status(directory.path(), value);
        let before = SystemTime::now();
        let sources = open(db(directory.path()), &settings("")).unwrap();
        let next = sources.next_check_at().expect("a check is scheduled");
        assert!(
            next <= before + STARTUP_DELAY + 2 * HOUR,
            "{value}: {next:?}"
        );
        assert!(sources.status.lock().last_checked_at.is_none(), "{value}");
        sources.record(Ok((Vec::new(), false)));
        let record = stored_status(directory.path()).expect("the status is stored");
        assert!(record.contains("last_checked_at"), "{value}: {record}");
    }
}

/// The wait `due` gives after a check `HOUR` before `now`, counted from that
/// check.
fn wait_after(schedule: &Schedule, checked: &str, failures: u32) -> Duration {
    let checked = SystemTime::from(utc(checked));
    let now = checked + HOUR;
    due(schedule, Some(checked), failures, now, &Utc)
        .unwrap()
        .duration_since(checked)
        .unwrap()
}

fn utc(text: &str) -> DateTime<Utc> {
    chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M")
        .unwrap()
        .and_utc()
}

fn cron(expression: &str) -> Schedule {
    Schedule::Cron(Cron::parse(expression).unwrap())
}

#[test]
fn backoff_starts_at_an_hour_doubles_and_stops_at_the_interval() {
    let daily = Schedule::Interval(24);
    let wait = |failures| wait_after(&daily, "2026-11-11 12:00", failures);
    assert_eq!(wait(0), 24 * HOUR);
    assert_eq!(
        wait(1),
        HOUR + STARTUP_DELAY,
        "the startup delay counts from now"
    );
    assert_eq!(wait(2), 2 * HOUR);
    assert_eq!(wait(5), 16 * HOUR);
    assert_eq!(wait(6), 24 * HOUR);
    assert_eq!(wait(u32::MAX), 24 * HOUR);
    assert_eq!(
        wait_after(&Schedule::Interval(6), "2026-11-11 12:00", 4),
        6 * HOUR
    );
}

#[test]
fn a_cron_check_comes_at_the_next_time_it_names() {
    let daily = cron("0 3 * * *");
    assert_eq!(
        wait_after(&daily, "2026-11-11 03:20", 0),
        23 * HOUR + 40 * 60 * SECOND
    );
    assert_eq!(wait_after(&daily, "2026-11-11 01:00", 0), 2 * HOUR);
    // Failures back off from the last check but never past the next fire.
    assert_eq!(wait_after(&daily, "2026-11-11 03:20", 2), 2 * HOUR);
    assert_eq!(wait_after(&daily, "2026-11-11 03:20", 5), 16 * HOUR);
    assert_eq!(
        wait_after(&daily, "2026-11-11 03:20", 6),
        23 * HOUR + 40 * 60 * SECOND
    );
    assert_eq!(wait_after(&daily, "2026-11-11 01:00", 3), 2 * HOUR);
    let zone = chrono::FixedOffset::east_opt(10 * 3600).unwrap();
    let checked = SystemTime::from(utc("2026-11-11 00:00"));
    assert_eq!(
        due(&daily, Some(checked), 0, checked, &zone),
        Some(SystemTime::from(utc("2026-11-11 17:00"))),
        "03:00 in the given zone"
    );
}

#[test]
fn a_missed_or_unknown_cron_check_waits_only_the_startup_delay() {
    let daily = cron("0 3 * * *");
    let now = SystemTime::from(utc("2026-11-11 12:00"));
    let soon = Some(now + STARTUP_DELAY);
    for checked in [
        None,
        Some(utc("2026-11-10 02:00")),
        Some(utc("2026-11-09 12:00")),
        Some(utc("2026-11-12 12:00")),
    ] {
        let checked = checked.map(SystemTime::from);
        assert_eq!(due(&daily, checked, 0, now, &Utc), soon, "{checked:?}");
        assert_eq!(due(&daily, checked, 3, now, &Utc), soon, "{checked:?}");
    }
    assert_eq!(
        due(&daily, Some(now - STARTUP_DELAY), 0, now, &Utc),
        Some(SystemTime::from(utc("2026-11-12 03:00")))
    );
}

#[test]
fn each_scheduled_wait_adds_at_most_an_hour() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    sources
        .apply(patch(
            json!({"auto_update": {"enabled": true, "interval_hours": 6}}),
        ))
        .unwrap();
    let within = |base: Duration| {
        let checked = sources.status.lock().last_checked_at.unwrap();
        let wait = sources
            .next_check_at()
            .unwrap()
            .duration_since(checked)
            .unwrap();
        assert!(wait >= base && wait <= base + HOUR, "{wait:?}");
    };
    for _ in 0..32 {
        sources.record(Err("download_failed".into()));
    }
    within(6 * HOUR);
    for _ in 0..64 {
        sources.record(Ok((Vec::new(), false)));
        within(6 * HOUR);
    }
    sources.record(Err("download_failed".into()));
    within(HOUR);
    sources.record(Err("download_failed".into()));
    within(2 * HOUR);
    sources
        .apply(patch(json!({"auto_update": {"enabled": false}})))
        .unwrap();
    assert_eq!(sources.next_check_at(), None);
}

fn stored_record(directory: &std::path::Path) -> Option<String> {
    db(directory)
        .strict()
        .query_row(
            "SELECT record FROM geodata_settings WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
}

#[test]
fn the_file_seeds_only_the_asset_it_names() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(
        db(directory.path()),
        &settings("https://config.example/geosite.dat"),
    )
    .unwrap();
    let seeded = sources.effective();
    assert_eq!(seeded.source, Source::Config);
    assert_eq!(seeded.urls[1], DEFAULT_URLS[1].map(str::to_owned).to_vec());
    let record = stored_record(directory.path()).unwrap();
    assert!(record.contains("https://config.example/geosite.dat"));
    assert!(!record.contains("geoip"), "{record}");
}

#[test]
fn a_list_the_file_no_longer_names_is_deleted_at_startup() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(
        db(directory.path()),
        &settings("https://config.example/geosite.dat"),
    )
    .unwrap();
    sources
        .apply(patch(
            json!({"auto_update": {"enabled": true, "interval_hours": 48}}),
        ))
        .unwrap();
    drop(sources);
    let sources = open(db(directory.path()), &settings("")).unwrap();
    let effective = sources.effective();
    assert_eq!(effective.source, Source::Default);
    assert_eq!(
        effective.urls[0],
        DEFAULT_URLS[0].map(str::to_owned).to_vec()
    );
    assert_eq!(
        effective.auto_update,
        AutoUpdate {
            enabled: true,
            schedule: Schedule::Interval(48)
        }
    );
}

#[test]
fn an_unusable_stored_record_is_ignored_and_the_defaults_apply() {
    for record in [
        "not json",
        r#"{"auto_update":{"enabled":true,"interval_hours":1}}"#,
        r#"{"auto_update":{"enabled":true}}"#,
        r#"{"auto_update":{"enabled":true,"interval_hours":24,"cron":"0 3 * * *"}}"#,
        r#"{"auto_update":{"enabled":true,"cron":"0 0 31 2 *"}}"#,
        r#"{"auto_update":{"enabled":true,"cron":"0 3 * * *","jitter":true}}"#,
        r#"{"verify_checksum_from_config":true}"#,
    ] {
        let directory = tempfile::tempdir().unwrap();
        db(directory.path())
            .strict()
            .execute(
                "INSERT INTO geodata_settings (id, record) VALUES (1, ?1)",
                [record],
            )
            .unwrap();
        let sources = open(db(directory.path()), &settings("")).unwrap();
        assert_eq!(sources.effective(), effective(&Stored::default()));
        let patched = sources
            .apply(patch(json!({"auto_update": {"enabled": true}})))
            .unwrap();
        assert!(patched.auto_update.enabled);
        assert_ne!(stored_record(directory.path()).unwrap(), record);
    }
}

fn detour(value: &str) -> NativeApiConfig {
    NativeApiConfig {
        geodata_download_detour: value.into(),
        ..Default::default()
    }
}

/// A patch as the settings handler stores it, the group id already resolved.
fn named(value: Value) -> Option<Patch> {
    let mut patch = patch(value);
    if let Some(patch) = patch.as_mut() {
        assert!(patch.resolve_group(|id| (id == "group-id").then(|| "proxy".to_owned())));
    }
    patch
}

#[test]
fn downloads_follow_routing_until_a_route_is_stored() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    assert_eq!(sources.effective().download, Route::Routing);
    let routed = sources
        .apply(named(
            json!({"download": {"route": "group", "group_id": "group-id"}}),
        ))
        .unwrap();
    assert_eq!(routed.download, Route::Group("proxy".into()));
    assert_eq!(
        routed.source,
        Source::Default,
        "the route does not change source"
    );
    assert_eq!(
        routed.json(str::to_owned, |name| (name == "proxy")
            .then(|| "group-id".to_owned()))["download"],
        json!({"route": "group", "group_id": "group-id"})
    );
    assert_eq!(
        routed.json(str::to_owned, |_| None)["download"],
        json!({"route": "group", "group_id": null}),
        "a group that no longer exists reads null"
    );
    drop(sources);
    let reopened = open(db(directory.path()), &settings("")).unwrap();
    assert_eq!(reopened.effective().download, Route::Group("proxy".into()));
    let reset = reopened.apply(None).unwrap();
    assert_eq!(reset.download, Route::Routing);
}

#[test]
fn the_file_seeds_the_download_route_at_startup_over_a_patch() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open(db(directory.path()), &detour("proxy")).unwrap();
    assert_eq!(sources.effective().download, Route::Group("proxy".into()));
    sources
        .apply(named(json!({"download": {"route": "direct"}})))
        .unwrap();
    assert_eq!(sources.effective().download, Route::Direct);
    drop(sources);
    let sources = open(db(directory.path()), &detour("routing")).unwrap();
    assert_eq!(sources.effective().download, Route::Routing);
    drop(sources);
    let sources = open(db(directory.path()), &detour("direct")).unwrap();
    assert_eq!(sources.effective().download, Route::Direct);
    drop(sources);
    let sources = open(db(directory.path()), &detour("proxy")).unwrap();
    drop(sources);
    let sources = open(db(directory.path()), &detour("")).unwrap();
    assert_eq!(
        sources.effective().download,
        Route::Routing,
        "a route an earlier file wrote is deleted"
    );
    sources
        .apply(named(json!({"download": {"route": "direct"}})))
        .unwrap();
    drop(sources);
    let sources = open(db(directory.path()), &detour("")).unwrap();
    assert_eq!(
        sources.effective().download,
        Route::Direct,
        "a patched route is kept"
    );
}

#[test]
fn download_patches_name_a_group_only_for_the_group_route() {
    for value in [
        json!({"download": {"route": "group"}}),
        json!({"download": {"route": "direct", "group_id": "group-id"}}),
        json!({"download": {"route": "routing", "group_id": "group-id"}}),
        json!({"download": {"route": "group", "group_id": ""}}),
        json!({"download": {"route": "proxy"}}),
        json!({"download": {}}),
    ] {
        assert!(Patch::parse(value.clone(), invalid).is_err(), "{value}");
    }
    let mut unknown = patch(json!({"download": {"route": "group", "group_id": "gone"}})).unwrap();
    assert!(!unknown.resolve_group(|_| None));
    let mut direct = patch(json!({"download": {"route": "direct"}})).unwrap();
    assert!(
        direct.resolve_group(|_| None),
        "only a group route looks the id up"
    );
}

#[test]
fn checksum_verification_is_on_until_a_patch_turns_it_off() {
    let directory = tempfile::tempdir().unwrap();
    db(directory.path())
        .strict()
        .execute(
            "INSERT INTO geodata_settings (id, record) VALUES (1, ?1)",
            [r#"{"auto_update":{"enabled":false,"interval_hours":48}}"#],
        )
        .unwrap();
    let sources = open(db(directory.path()), &settings("")).unwrap();
    assert!(sources.effective().verify_checksum, "an older record");
    let stored = sources
        .apply(patch(json!({"verify_checksum": false})))
        .unwrap();
    assert!(!stored.verify_checksum);
    assert!(!stored.auto_update.enabled);
    assert_eq!(
        stored.json(str::to_owned, |_| None)["verify_checksum"],
        false
    );
    drop(sources);
    let sources = open(db(directory.path()), &settings("")).unwrap();
    assert!(!sources.effective().verify_checksum);
    assert!(sources.apply(None).unwrap().verify_checksum);
    assert!(Patch::parse(json!({"verify_checksum": "no"}), invalid).is_err());
}

#[test]
fn the_assets_block_seeds_the_stored_sources_at_startup() {
    let config = honk_config::parser::parse_dae_config(
        "group {\n proxy { policy: min_moving_avg }\n}\nassets {\n route: proxy\n geodata {\n  geosite: 'https://assets.example/geosite.dat'\n  geoip: 'https://assets.example/geoip.dat'\n }\n}",
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let sources = Sources::open(
        db(directory.path()),
        &config.experimental.native_api,
        &config.assets.geodata,
    )
    .unwrap();
    let seeded = sources.effective();
    assert_eq!(seeded.source, Source::Config);
    assert_eq!(
        seeded.urls,
        [
            vec!["https://assets.example/geosite.dat".to_owned()],
            vec!["https://assets.example/geoip.dat".to_owned()],
        ]
    );
    assert_eq!(seeded.download, Route::Group("proxy".into()));
    sources
        .apply(named(json!({"download": {"route": "routing"}})))
        .unwrap();
    drop(sources);
    let config = honk_config::parser::parse_dae_config(
        "assets {\n route: routing\n geodata {\n  geosite: 'https://assets.example/geosite.dat'\n  route: direct\n }\n}",
    )
    .unwrap();
    let sources = Sources::open(
        db(directory.path()),
        &config.experimental.native_api,
        &config.assets.geodata,
    )
    .unwrap();
    assert_eq!(
        sources.effective().download,
        Route::Direct,
        "assets.geodata.route wins over assets.route"
    );
}

fn schedule_file(auto_update: Option<bool>, cron: Option<&str>) -> GeodataDefaults {
    GeodataDefaults {
        auto_update,
        cron: cron.map(|expression| Cron::parse(expression).unwrap()),
        checksum: None,
    }
}

fn open_with(directory: &std::path::Path, file: &GeodataDefaults) -> Sources {
    Sources::open(db(directory), &settings(""), file).unwrap()
}

#[test]
fn the_file_seeds_the_schedule_at_startup_over_a_patch() {
    let directory = tempfile::tempdir().unwrap();
    let sources = open_with(directory.path(), &schedule_file(Some(false), None));
    assert_eq!(
        sources.effective().auto_update,
        AutoUpdate {
            enabled: false,
            ..AutoUpdate::default()
        },
        "the cron defaults on its own"
    );
    assert!(
        stored_record(directory.path())
            .unwrap()
            .contains("from_config")
    );
    let patched = sources
        .apply(patch(json!({"auto_update": {"interval_hours": 48}})))
        .unwrap();
    assert_eq!(
        patched.auto_update,
        AutoUpdate {
            enabled: false,
            schedule: Schedule::Interval(48)
        },
        "a patch overrides the file until the next startup"
    );
    drop(sources);
    let sources = open_with(directory.path(), &schedule_file(None, Some("0 4 * * 1")));
    assert_eq!(
        sources.effective().auto_update,
        AutoUpdate {
            enabled: true,
            schedule: cron("0 4 * * 1")
        },
        "the file wins at startup and enabled defaults on its own"
    );
    drop(sources);
    let sources = open_with(directory.path(), &GeodataDefaults::default());
    assert_eq!(
        sources.effective().auto_update,
        AutoUpdate::default(),
        "a schedule an earlier file wrote is deleted"
    );
    sources
        .apply(patch(json!({"auto_update": {"cron": "15 5 * * *"}})))
        .unwrap();
    drop(sources);
    let sources = open_with(directory.path(), &GeodataDefaults::default());
    assert_eq!(
        sources.effective().auto_update.schedule,
        cron("15 5 * * *"),
        "a patched schedule is kept while the file is silent"
    );
    drop(sources);
    let sources = open_with(
        directory.path(),
        &schedule_file(Some(true), Some("0 2 * * *")),
    );
    assert_eq!(sources.effective().auto_update.schedule, cron("0 2 * * *"));
    assert_eq!(
        sources.effective().source,
        Source::Default,
        "source is about URLs"
    );
}

#[test]
fn the_file_seeds_checksum_verification_at_startup_over_a_patch() {
    let directory = tempfile::tempdir().unwrap();
    let off = GeodataDefaults {
        checksum: Some(false),
        ..GeodataDefaults::default()
    };
    let sources = open_with(directory.path(), &off);
    assert!(!sources.effective().verify_checksum);
    sources
        .apply(patch(json!({"verify_checksum": true})))
        .unwrap();
    drop(sources);
    let sources = open_with(directory.path(), &off);
    assert!(
        !sources.effective().verify_checksum,
        "the file wins at startup"
    );
    drop(sources);
    let sources = open_with(directory.path(), &GeodataDefaults::default());
    assert!(
        sources.effective().verify_checksum,
        "a value an earlier file wrote is deleted"
    );
    sources
        .apply(patch(json!({"verify_checksum": false})))
        .unwrap();
    drop(sources);
    let sources = open_with(directory.path(), &GeodataDefaults::default());
    assert!(
        !sources.effective().verify_checksum,
        "a patched value is kept while the file is silent"
    );
}

#[test]
fn a_record_from_before_cron_schedules_keeps_its_interval() {
    let directory = tempfile::tempdir().unwrap();
    store_settings(
        directory.path(),
        r#"{"urls":[{"urls":["https://mirror.example/geosite.dat"],"from_config":true},null],"auto_update":{"enabled":false,"interval_hours":48},"download":{"route":{"route":"direct"}},"verify_checksum":false}"#,
    );
    let sources = open(
        db(directory.path()),
        &settings("https://mirror.example/geosite.dat"),
    )
    .unwrap();
    let effective = sources.effective();
    assert_eq!(
        effective.auto_update,
        AutoUpdate {
            enabled: false,
            schedule: Schedule::Interval(48)
        }
    );
    assert!(!effective.verify_checksum);
    assert_eq!(effective.download, Route::Direct);
    assert_eq!(
        effective.json(str::to_owned, |_| None)["auto_update"],
        json!({"enabled": false, "interval_hours": 48, "cron": null})
    );
    let enabled = sources
        .apply(patch(json!({"auto_update": {"enabled": true}})))
        .unwrap();
    assert_eq!(
        enabled.auto_update.schedule,
        Schedule::Interval(48),
        "enabled alone keeps the mode"
    );
    let switched = sources
        .apply(patch(json!({"auto_update": {"cron": "0 */6 * * *"}})))
        .unwrap();
    assert_eq!(
        switched.json(str::to_owned, |_| None)["auto_update"],
        json!({"enabled": true, "interval_hours": 24, "cron": "0 */6 * * *"})
    );
    let back = sources
        .apply(patch(json!({"auto_update": {"interval_hours": 12}})))
        .unwrap();
    assert_eq!(back.auto_update.schedule, Schedule::Interval(12));
    let record = stored_record(directory.path()).unwrap();
    assert!(!record.contains("cron"), "{record}");
}

#[test]
fn auto_update_patches_name_one_schedule() {
    for value in [
        json!({"auto_update": {"interval_hours": 24, "cron": "0 3 * * *"}}),
        json!({"auto_update": {"cron": null}}),
        json!({"auto_update": {"cron": "0 3 * *"}}),
        json!({"auto_update": {"cron": "0 */4 * * *"}}),
        json!({"auto_update": {"cron": "0 0 31 2 *"}}),
        json!({"auto_update": {"cron": 3}}),
    ] {
        assert!(Patch::parse(value.clone(), invalid).is_err(), "{value}");
    }
    for value in [
        json!({"auto_update": {"enabled": false}}),
        json!({"auto_update": {"interval_hours": 6}}),
        json!({"auto_update": {"cron": "0 3 * * *"}}),
        json!({"auto_update": {"enabled": true, "cron": "0 3 * * *"}}),
    ] {
        assert!(Patch::parse(value.clone(), invalid).is_ok(), "{value}");
    }
}
