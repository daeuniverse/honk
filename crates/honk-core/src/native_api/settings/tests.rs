use super::*;

#[test]
fn invalid_cross_recorder_patch_is_atomic_and_activation_restores_config() {
    let mut config = Config::default();
    config.global.log_level = "WARN".into();
    let owner = NativeObservation::new(&config);
    let id = RequestId("settings-test".into());
    let first:Patch=serde_json::from_value(json!({"log":{"level":"debug","buffered_records":64},"flows":{"max_flows":64,"retention_seconds":1}})).unwrap();
    let current = owner
        .settings
        .patch(&owner, &config.experimental.native_api, first, &id)
        .unwrap();
    assert_eq!(current["source"], "runtime");
    let bad: Patch =
        serde_json::from_value(json!({"log":{"level":"trace"},"dns_log":{"max_records":513}}))
            .unwrap();
    assert!(
        owner
            .settings
            .patch(&owner, &config.experimental.native_api, bad, &id)
            .is_err()
    );
    let unchanged = owner.settings.snapshot();
    assert_eq!(unchanged["log"], current["log"]);
    assert_eq!(unchanged["flows"], current["flows"]);
    assert!(serde_json::from_value::<Patch>(json!({"record_flows":true})).is_err());
    let modes: Patch = serde_json::from_value(
        json!({"record_flows":"on","record_logs":"off","record_dns_log":"auto"}),
    )
    .unwrap();
    let changed = owner
        .settings
        .patch(&owner, &config.experimental.native_api, modes, &id)
        .unwrap();
    assert_eq!(changed["recording"]["flows"]["mode"], "on");
    assert_eq!(changed["recording"]["flows"]["active"], true);
    assert_eq!(changed["recording"]["logs"]["mode"], "off");
    assert_eq!(changed["recording"]["logs"]["active"], false);
    assert_eq!(changed["recording"]["dns_log"]["mode"], "auto");
    assert_eq!(owner.settings.flow_recording_policy(), "on");
    owner.settings.activate(&owner, &config);
    let restored = owner.settings.snapshot();
    assert_eq!(restored["source"], "config");
    assert_eq!(restored["log"]["level"], "warn");
    assert_eq!(restored["flows"]["max_flows"], 1024);
    assert_eq!(restored["recording"]["flows"]["mode"], "auto");
    assert_eq!(owner.settings.flow_recording_policy(), "auto");
    assert_eq!(restored["recording"]["logs"]["mode"], "auto");

    config.experimental.native_api.record_flows = false;
    let forbidden = NativeObservation::new(&config);
    let mixed =
        serde_json::from_value(json!({"record_flows":"on","log":{"level":"trace"}})).unwrap();
    assert!(
        forbidden
            .settings
            .patch(&forbidden, &config.experimental.native_api, mixed, &id)
            .is_err()
    );
    assert_eq!(forbidden.settings.snapshot()["log"]["level"], "warn");
    assert_eq!(
        forbidden.settings.snapshot()["recording"]["flows"]["active"],
        false
    );
    let auto = serde_json::from_value(json!({"record_flows":"auto"})).unwrap();
    assert!(
        forbidden
            .settings
            .patch(&forbidden, &config.experimental.native_api, auto, &id)
            .is_ok()
    );
    forbidden.settings.renew(&forbidden, Demand::FLOWS);
    assert!(!forbidden.settings.flow_recording());
    assert_eq!(forbidden.settings.flow_recording_policy(), "off");
    assert_eq!(
        forbidden.settings.snapshot()["recording"]["flows"]["active"],
        false
    );
}
#[test]
fn a_runtime_level_reaches_console_and_file_until_activation() {
    use tracing_subscriber::{EnvFilter, prelude::*};
    if super::super::logs::tests::run_isolated(
        "native_api::settings::tests::a_runtime_level_reaches_console_and_file_until_activation",
    ) {
        return;
    }
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut config = Config::default();
    config.global.log_level = "warn".into();
    let owner = NativeObservation::new(&config);
    let mut engine = super::super::logs::EngineLevel::default();
    let mut sinks = Vec::new();
    let mut layers = Vec::new();
    for _ in ["console", "file"] {
        let sink = Sink::default();
        let writer = sink.clone();
        let (filter, handle) = tracing_subscriber::reload::Layer::new(EnvFilter::new("warn"));
        engine.push(handle, EnvFilter::new("warn"));
        layers.push(
            tracing_subscriber::fmt::layer()
                .with_writer(move || writer.clone())
                .with_filter(filter)
                .boxed(),
        );
        sinks.push(sink);
    }
    owner.logs.attach_engine_level(engine);
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layers));
    let emitted = || {
        tracing::dispatcher::with_default(&dispatch, || tracing::debug!("level probe"));
        sinks
            .iter()
            .map(|sink| !std::mem::take(&mut *sink.0.lock()).is_empty())
            .collect::<Vec<_>>()
    };
    let id = RequestId("settings-test".into());
    let patch = |body: Value| {
        owner
            .settings
            .patch(
                &owner,
                &config.experimental.native_api,
                serde_json::from_value(body).unwrap(),
                &id,
            )
            .unwrap();
    };

    assert_eq!(emitted(), [false, false]);
    patch(json!({"log":{"level":"debug"}}));
    assert_eq!(emitted(), [true, true]);
    patch(json!({"log":{"buffered_records":64}}));
    assert_eq!(emitted(), [true, true]);
    owner.settings.activate(&owner, &config);
    assert_eq!(emitted(), [false, false]);
}

fn stream(owner: &NativeObservation, demand: Demand) -> super::super::events::Subscription {
    let request = axum::extract::Request::builder()
        .uri("/api/v1/events")
        .body(axum::body::Body::empty())
        .unwrap();
    owner
        .settings
        .subscribe(owner, demand, || owner.events.subscribe_for_test(&request))
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn attachment_gate_and_grace_expiry_control_requested_recorders() {
    use futures::StreamExt;
    let owner = NativeObservation::new(&Config::default());
    let active = |expected| {
        let value = owner.settings.snapshot();
        for recorder in ["flows", "logs", "dns_log", "events"] {
            assert_eq!(
                value["recording"][recorder]["active"],
                expected && matches!(recorder, "flows" | "events"),
                "{recorder}"
            );
        }
    };
    active(false);
    assert!(owner.events.buffered_kinds().is_empty());
    owner.events.publish("runtime.updated", json!({}), None);
    assert!(owner.events.buffered_kinds().is_empty());
    let mut first = stream(&owner, Demand::FLOWS);
    let ready = first.next().await.unwrap().unwrap();
    active(true);
    let second = stream(&owner, Demand::FLOWS);
    drop(first);
    tokio::time::advance(Duration::from_secs(61)).await;
    owner.settings.maintain(&owner);
    active(true);
    drop(second);
    assert_eq!(
        owner.settings.snapshot()["recording"]["grace_remaining_seconds"],
        60
    );
    tokio::time::advance(Duration::from_secs(59)).await;
    owner.settings.maintain(&owner);
    active(true);
    tokio::time::advance(Duration::from_secs(1)).await;
    active(true);
    owner.settings.maintain(&owner);
    active(false);
    let cursor = std::str::from_utf8(&ready)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .unwrap();
    let request = axum::extract::Request::builder()
        .uri("/api/v1/events")
        .header("last-event-id", cursor)
        .body(axum::body::Body::empty())
        .unwrap();
    assert!(
        owner
            .settings
            .subscribe(&owner, Demand::FLOWS, || owner
                .events
                .subscribe_for_test(&request))
            .is_err()
    );
    active(false);
    owner.settings.renew(&owner, Demand::FLOWS);
    active(true);
    assert_eq!(owner.events.buffered_kinds(), vec!["flow.gap"]);
    tokio::time::advance(Duration::from_secs(60)).await;
    owner.settings.maintain(&owner);
    active(false);
    owner.settings.shutdown(&owner);
    owner.settings.renew(&owner, Demand::FLOWS);
    active(false);
}

#[tokio::test(start_paused = true)]
async fn unpolled_and_overflowed_subscriptions_release_attachment_once() {
    let owner = NativeObservation::new(&Config::default());
    let demand = Demand {
        flows: true,
        logs: true,
        dns_log: true,
    };
    let unpolled = stream(&owner, demand);
    drop(unpolled);
    tokio::time::advance(Duration::from_secs(60)).await;
    owner.settings.maintain(&owner);
    assert!(!owner.settings.flow_recording());
    for recorder in ["flows", "logs", "dns_log", "events"] {
        assert_eq!(
            owner.settings.snapshot()["recording"][recorder]["active"],
            false
        );
    }
    let overflow = stream(&owner, demand);
    for _ in 0..65 {
        owner.events.publish("runtime.updated", json!({}), None);
    }
    assert_eq!(
        owner.settings.snapshot()["recording"]["grace_remaining_seconds"],
        60
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    owner.settings.maintain(&owner);
    assert!(!owner.settings.flow_recording());
    for recorder in ["flows", "logs", "dns_log", "events"] {
        assert_eq!(
            owner.settings.snapshot()["recording"][recorder]["active"],
            false
        );
    }
    drop(overflow);
    assert_eq!(
        owner.settings.snapshot()["recording"]["grace_remaining_seconds"],
        0
    );
}

#[tokio::test(start_paused = true)]
async fn flow_demand_expires_independently_of_activity_and_dns_polls() {
    use futures::StreamExt;
    let owner = NativeObservation::new(&Config::default());
    let mut activity = stream(&owner, Demand::NONE);
    activity.next().await.unwrap().unwrap();
    owner.events.publish("runtime.updated", json!({}), None);
    let update = activity.next().await.unwrap().unwrap();
    assert!(
        std::str::from_utf8(&update)
            .unwrap()
            .starts_with("event: runtime.updated\n")
    );
    assert!(!owner.settings.flow_recording());
    assert!(
        owner
            .core
            .flows
            .begin(
                crate::observe::vocab::Network::Tcp,
                "127.0.0.1:31000".parse().unwrap(),
                "127.0.0.2:443".parse().unwrap(),
            )
            .is_none()
    );
    let logs = stream(&owner, Demand::LOGS);
    let first = stream(&owner, Demand::FLOWS);
    let second = stream(&owner, Demand::FLOWS);
    let flow = owner
        .core
        .flows
        .begin(
            crate::observe::vocab::Network::Tcp,
            "127.0.0.1:31000".parse().unwrap(),
            "127.0.0.2:443".parse().unwrap(),
        )
        .unwrap();
    assert!(owner.core.flows.connection_evidence(flow.id()).is_some());
    drop(first);
    drop(logs);
    tokio::time::advance(Duration::from_secs(61)).await;
    owner.settings.maintain(&owner);
    assert!(owner.settings.flow_recording());
    assert_eq!(
        owner.settings.snapshot()["recording"]["logs"]["active"],
        false
    );
    assert_eq!(
        owner.settings.snapshot()["recording"]["dns_log"]["active"],
        false
    );
    drop(second);
    tokio::time::advance(Duration::from_secs(59)).await;
    owner.settings.renew(&owner, Demand::DNS_LOG);
    owner.settings.maintain(&owner);
    assert!(owner.core.flows.connection_evidence(flow.id()).is_some());
    tokio::time::advance(Duration::from_secs(1)).await;
    owner.settings.maintain(&owner);
    assert!(!owner.settings.flow_recording());
    assert!(owner.core.flows.connection_evidence(flow.id()).is_none());
    let settings = owner.settings.snapshot();
    assert_eq!(settings["recording"]["logs"]["active"], false);
    assert_eq!(settings["recording"]["dns_log"]["active"], true);
    assert_eq!(settings["recording"]["events"]["active"], true);
    owner.settings.renew(&owner, Demand::FLOWS);
    assert!(owner.settings.flow_recording());
    tokio::time::advance(Duration::from_secs(59)).await;
    owner.settings.renew(&owner, Demand::FLOWS);
    tokio::time::advance(Duration::from_secs(59)).await;
    owner.settings.maintain(&owner);
    assert!(owner.settings.flow_recording());
    tokio::time::advance(Duration::from_secs(1)).await;
    owner.settings.maintain(&owner);
    assert!(!owner.settings.flow_recording());
    drop(activity);
}

#[tokio::test(start_paused = true)]
async fn recorder_modes_and_activation_preserve_separate_demand() {
    for (field, recorder, demand) in [
        ("record_flows", "flows", Demand::FLOWS),
        ("record_logs", "logs", Demand::LOGS),
        ("record_dns_log", "dns_log", Demand::DNS_LOG),
    ] {
        let config = Config::default();
        let owner = NativeObservation::new(&config);
        let id = RequestId("demand-test".into());
        let activity = stream(&owner, Demand::NONE);
        let patch = |mode| {
            owner
                .settings
                .patch(
                    &owner,
                    &config.experimental.native_api,
                    serde_json::from_value(json!({(field): mode})).unwrap(),
                    &id,
                )
                .unwrap()
        };
        let active = || owner.settings.snapshot()["recording"][recorder]["active"].clone();
        assert_eq!(patch("on")["recording"][recorder]["active"], true);
        tokio::time::advance(Duration::from_secs(61)).await;
        owner.settings.maintain(&owner);
        assert_eq!(active(), true);
        owner.settings.activate(&owner, &config);
        assert_eq!(active(), false);
        let diagnostic = stream(&owner, demand);
        assert_eq!(patch("off")["recording"][recorder]["active"], false);
        owner.settings.renew(&owner, demand);
        assert_eq!(active(), false);
        owner.settings.activate(&owner, &config);
        assert_eq!(active(), true);
        // Release must use the acquired set even after an override disables it.
        patch("off");
        drop(diagnostic);
        owner.settings.activate(&owner, &config);
        assert_eq!(active(), true);
        tokio::time::advance(Duration::from_secs(60)).await;
        owner.settings.maintain(&owner);
        assert_eq!(active(), false);
        assert_eq!(
            owner.settings.snapshot()["recording"]["events"]["active"],
            true
        );
        owner.settings.shutdown(&owner);
        owner.settings.activate(&owner, &config);
        let after_shutdown = stream(&owner, demand);
        owner.settings.renew(&owner, demand);
        owner.settings.maintain(&owner);
        assert_eq!(active(), false);
        drop((activity, after_shutdown));

        let mut config = config;
        config.experimental.native_api.record_flows = false;
        config.experimental.native_api.record_logs = false;
        config.experimental.native_api.record_dns_log = false;
        let forbidden = NativeObservation::new(&config);
        let admitted = stream(&forbidden, demand);
        assert_eq!(
            forbidden.settings.snapshot()["recording"][recorder]["active"],
            false
        );
        assert_eq!(
            forbidden.settings.snapshot()["recording"]["events"]["active"],
            true
        );
        let on = serde_json::from_value(json!({(field): "on"})).unwrap();
        assert!(
            forbidden
                .settings
                .patch(&forbidden, &config.experimental.native_api, on, &id)
                .is_err()
        );
        drop(admitted);
    }
}
