use super::*;

const HOUR: Duration = Duration::from_secs(3600);

fn db(directory: &std::path::Path) -> Arc<StateDb> {
    Arc::new(StateDb::open_for_test(directory, 28672))
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
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
    sources
        .apply(patch(
            json!({"geosite": {"urls": ["https://patched.example/geosite.dat"]},
            "geoip": {"urls": ["https://patched.example/geoip.dat"]}}),
        ))
        .unwrap();
    assert_eq!(sources.effective().source, Source::Override);
    drop(sources);
    let sources = Sources::open(
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
    let first = Sources::open(
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
    let second = Sources::open(
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
            interval_hours: 48
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
    let sources = Sources::open(db(directory.path()), &file).unwrap();
    sources
        .apply(patch(
            json!({"geosite": {"urls": ["https://patched.example/geosite.dat"]}}),
        ))
        .unwrap();
    drop(sources);
    let reopened = Sources::open(db(directory.path()), &settings(""))
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
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
    assert_eq!(sources.effective().source, Source::Default);
    let stored = sources
        .apply(patch(
            json!({"geosite": {"urls": ["https://mirror.example/geosite.dat"]},
            "auto_update": {"interval_hours": 48}}),
        ))
        .unwrap();
    assert_eq!(stored.source, Source::Override);
    assert_eq!(stored.urls[1], DEFAULT_URLS[1].map(str::to_owned).to_vec());
    assert_eq!(stored.auto_update.interval_hours, 48);
    drop(sources);
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
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
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
    assert!(sources.effective().auto_update.enabled);
}

#[test]
fn the_default_interval_is_a_day() {
    let directory = tempfile::tempdir().unwrap();
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
    assert_eq!(sources.effective().auto_update.interval_hours, 24);
}

#[test]
fn startup_waits_one_interval_before_the_first_check() {
    let directory = tempfile::tempdir().unwrap();
    let before = SystemTime::now();
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
    let after = SystemTime::now();
    let next = sources.next_check_at().expect("a check is scheduled");
    assert!(next >= before + 24 * HOUR, "{next:?}");
    assert!(next <= after + 25 * HOUR, "{next:?}");
}

#[test]
fn backoff_starts_at_an_hour_doubles_and_stops_at_the_interval() {
    let daily = AutoUpdate {
        enabled: true,
        interval_hours: 24,
    };
    assert_eq!(wait(daily, 0), 24 * HOUR);
    assert_eq!(wait(daily, 1), HOUR);
    assert_eq!(wait(daily, 2), 2 * HOUR);
    assert_eq!(wait(daily, 5), 16 * HOUR);
    assert_eq!(wait(daily, 6), 24 * HOUR);
    assert_eq!(wait(daily, u32::MAX), 24 * HOUR);
    let short = AutoUpdate {
        enabled: true,
        interval_hours: 6,
    };
    assert_eq!(wait(short, 4), 6 * HOUR);
}

#[test]
fn each_scheduled_wait_adds_at_most_an_hour() {
    let directory = tempfile::tempdir().unwrap();
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
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
    let sources = Sources::open(
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
    let sources = Sources::open(
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
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
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
            interval_hours: 48
        }
    );
}

#[test]
fn an_unusable_stored_record_is_ignored_and_the_defaults_apply() {
    for record in [
        "not json",
        r#"{"auto_update":{"enabled":true,"interval_hours":1}}"#,
    ] {
        let directory = tempfile::tempdir().unwrap();
        db(directory.path())
            .strict()
            .execute(
                "INSERT INTO geodata_settings (id, record) VALUES (1, ?1)",
                [record],
            )
            .unwrap();
        let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
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
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
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
    let reopened = Sources::open(db(directory.path()), &settings("")).unwrap();
    assert_eq!(reopened.effective().download, Route::Group("proxy".into()));
    let reset = reopened.apply(None).unwrap();
    assert_eq!(reset.download, Route::Routing);
}

#[test]
fn the_file_seeds_the_download_route_at_startup_over_a_patch() {
    let directory = tempfile::tempdir().unwrap();
    let sources = Sources::open(db(directory.path()), &detour("proxy")).unwrap();
    assert_eq!(sources.effective().download, Route::Group("proxy".into()));
    sources
        .apply(named(json!({"download": {"route": "direct"}})))
        .unwrap();
    assert_eq!(sources.effective().download, Route::Direct);
    drop(sources);
    let sources = Sources::open(db(directory.path()), &detour("routing")).unwrap();
    assert_eq!(sources.effective().download, Route::Routing);
    drop(sources);
    let sources = Sources::open(db(directory.path()), &detour("direct")).unwrap();
    assert_eq!(sources.effective().download, Route::Direct);
    drop(sources);
    let sources = Sources::open(db(directory.path()), &detour("proxy")).unwrap();
    drop(sources);
    let sources = Sources::open(db(directory.path()), &detour("")).unwrap();
    assert_eq!(
        sources.effective().download,
        Route::Routing,
        "a route an earlier file wrote is deleted"
    );
    sources
        .apply(named(json!({"download": {"route": "direct"}})))
        .unwrap();
    drop(sources);
    let sources = Sources::open(db(directory.path()), &detour("")).unwrap();
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
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
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
    let sources = Sources::open(db(directory.path()), &settings("")).unwrap();
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
    let sources = Sources::open(db(directory.path()), &config.experimental.native_api).unwrap();
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
    let sources = Sources::open(db(directory.path()), &config.experimental.native_api).unwrap();
    assert_eq!(
        sources.effective().download,
        Route::Direct,
        "assets.geodata.route wins over assets.route"
    );
}
