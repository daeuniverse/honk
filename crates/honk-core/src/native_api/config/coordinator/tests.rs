use super::*;

#[test]
fn a_written_but_unconfirmed_replacement_is_not_retryable() {
    let response = write_error(WriteError::ChangedButNotDurable).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("retry-after").is_none());
}

#[test]
fn store_refusals_keep_the_write_stage_and_name_the_reason() {
    for (error, reason) in [
        (WriteError::UnsafePath, "unsafe_path"),
        (WriteError::SecretSource, "listener_secret_source"),
        (WriteError::SecretContent, "listener_secret_in_content"),
    ] {
        let error = write_error(error);
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(
            error.into_details(),
            Some(json!({"stage":"write","reason":reason}))
        );
    }
}

#[test]
fn source_and_management_admission_share_disabled_and_unavailable_priority() {
    for config_write in [false, true] {
        let mut config = Config::default();
        config.experimental.native_api.config_write = config_write;
        config.experimental.native_api.secret = "listener-token".into();
        let owner = crate::native_api::observation::NativeObservation::new(&config);
        let service = &owner.configuration;
        let reason = if config_write {
            WriteRefusal::ConfigurationUnavailable
        } else {
            WriteRefusal::WritesDisabled
        };
        assert_eq!(service.write_refusal(), Some(reason));
        assert_eq!(
            service.manage_admission().unwrap_err().into_details(),
            Some(json!({"reason":reason.as_str()}))
        );
    }
}

fn source_tree() -> (tempfile::TempDir, PathBuf, LoadedConfig) {
    let directory = tempfile::tempdir().unwrap();
    let entry = directory.path().join("main.dae");
    std::fs::write(
        &entry,
        "include { 'auth.dae' }\nglobal { nfqueue_enable: false }\nrouting { fallback: direct }\n",
    )
    .unwrap();
    std::fs::write(directory.path().join("auth.dae"), "experimental { native_api { enabled: true\n config_write: true\n secret: 'listener-token' } }\n").unwrap();
    let loaded = Config::from_dae_file_with_sources(
        &entry,
        &HashMap::new(),
        SourceLimits::DEFAULT,
        &mut Vec::new(),
    )
    .unwrap();
    (directory, entry, loaded)
}

#[test]
fn source_and_management_admission_agree_when_the_receiver_is_closed() {
    let (_directory, _entry, loaded) = source_tree();
    let owner = crate::native_api::observation::NativeObservation::new(&loaded.config);
    let service = &owner.configuration;
    let update = SourceUpdate {
        sources: loaded.sources,
        dependencies: vec![],
        geo_sources: None,
    };
    service
        .sources
        .accept(service.sources.prepare_accept(&update), 0);
    let (sender, receiver) = mpsc::channel(1);
    *service.sender.lock() = Some(sender);
    drop(receiver);
    assert_eq!(
        service.write_refusal(),
        Some(WriteRefusal::ConfigurationUnavailable)
    );
    assert_eq!(
        service.manage_admission().unwrap_err().into_details(),
        Some(json!({"reason":"configuration_unavailable"}))
    );
}

#[test]
fn candidate_secret_refusals_precede_listener_settings_changes() {
    let (directory, entry, loaded) = source_tree();
    let owner = crate::native_api::observation::NativeObservation::new(&loaded.config);
    let update = SourceUpdate {
        sources: loaded.sources.clone(),
        dependencies: vec![],
        geo_sources: None,
    };
    owner
        .configuration
        .sources
        .accept(owner.configuration.sources.prepare_accept(&update), 0);
    let accepted = owner.configuration.sources.accepted.read().clone().unwrap();
    let check = CandidateCheck {
        store: SourceStore::File(entry.clone().into()),
        secrets: ListenerSecrets::from_config(&loaded.config),
        active: Arc::new(loaded.config),
        log_files: LogFiles::default(),
        data_dir: directory.path().to_path_buf(),
        deferred: vec![],
    };
    for (extra, drift, reason) in [
        (
            "experimental { native_api { record_logs: false\n secret: 'listener-token' } }\n",
            false,
            "listener_secret_source",
        ),
        (
            "# listener-token\nexperimental { native_api { record_logs: false } }\n",
            false,
            "listener_secret_in_content",
        ),
        (
            "experimental { native_api { record_logs: false } }\n",
            true,
            "credential_sources_changed",
        ),
        (
            "experimental { native_api { record_logs: false } }\n",
            false,
            "listener_settings_changed",
        ),
    ] {
        let content = format!("{}{extra}", update.sources[0].content);
        let mut overlay = HashMap::from([(entry.clone(), Arc::<str>::from(content.as_str()))]);
        if drift {
            let auth = &update.sources[1];
            overlay.insert(
                auth.path.clone(),
                Arc::from(format!("{}# disk edit\n", auth.content)),
            );
        }
        let candidate = Config::from_dae_file_with_sources(
            &entry,
            &overlay,
            SourceLimits::DEFAULT,
            &mut Vec::new(),
        )
        .unwrap();
        let error = check
            .validate(
                candidate,
                &mut Vec::new(),
                Some((&accepted, &entry, &content)),
                None,
                None,
            )
            .err()
            .unwrap();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.into_details(), Some(json!({"reason":reason})));
    }
}

#[test]
fn db_import_secret_copy_keeps_its_status_details_and_reason() {
    let (directory, entry, _) = source_tree();
    let state = directory.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let main = std::fs::read_to_string(&entry).unwrap();
    std::fs::write(
        &entry,
        format!("{main}global {{ data_dir: '{}' }}\n", state.display()),
    )
    .unwrap();
    let mut startup =
        super::super::super::store::DatabaseStartup::open(&entry, &state, &mut Vec::new()).unwrap();
    startup.record().unwrap();
    std::fs::write(
        &entry,
        format!(
            "{}# listener-token\n",
            std::fs::read_to_string(&entry).unwrap()
        ),
    )
    .unwrap();
    let error = revisions::read_import(&startup.store, &mut Vec::new())
        .err()
        .unwrap();
    assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error.error.code.as_str(), "unsupported_value");
    assert_eq!(
        error.into_details(),
        Some(
            json!({"resource":"/x-honk/config/import", "check":"secret_copy", "reason":"listener_secret_in_content"})
        )
    );
    assert_eq!(startup.store.head(), Ok(Some(1)));
}
