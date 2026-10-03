use super::*;
use std::collections::HashMap;

fn fixture(directory: &Path, extra: &str) -> LoadedConfig {
    let path = directory.join("config.dae");
    let text = format!(
        "global {{ data_dir: '{}'\n nfqueue_enable: false\n dial_mode: ip }}\nrouting {{ fallback: direct }}\n{extra}",
        directory.join("state").display(),
    );
    fs::write(&path, text).unwrap();
    Config::from_dae_file_with_sources(
        &path,
        &HashMap::new(),
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
}

fn admit(loaded: LoadedConfig, active: &Config) -> Result<ValidatedConfig, DetailedConfigError> {
    admit_with_limits(loaded, active, SourceLimits::default())
}

fn admit_with_limits(
    loaded: LoadedConfig,
    active: &Config,
    limits: SourceLimits,
) -> Result<ValidatedConfig, DetailedConfigError> {
    validate_with_data_dir(
        loaded,
        active,
        Path::new(&active.global.data_dir),
        limits,
        &mut Vec::new(),
    )
}

#[test]
fn effective_root_overrides_requested_data_directory() {
    let temp = tempfile::tempdir().unwrap();
    let effective = tempfile::tempdir().unwrap();
    let loaded = fixture(temp.path(), "dns { use_host: 'hosts.rules' }");
    let active = loaded.config.clone();
    let requested = Path::new(&active.global.data_dir);
    fs::create_dir(requested).unwrap();
    fs::write(
        requested.join("hosts.rules"),
        "full:requested.test 192.0.2.1\n",
    )
    .unwrap();
    let selected = effective.path().join("hosts.rules");
    fs::write(&selected, "full:effective.test 192.0.2.2\n").unwrap();
    let result = validate_with_data_dir(
        loaded,
        &active,
        effective.path(),
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        result.dependencies[0].path,
        fs::canonicalize(selected).unwrap()
    );
}

#[test]
fn offline_admission_does_not_create_runtime_state_or_connect() {
    let temp = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut loaded = fixture(temp.path(), "");
    let active = loaded.config.clone();
    let sources = loaded.sources.clone();
    let admitted = admit(loaded.clone(), &active).unwrap();
    assert!(
        admitted
            .config
            .nodes
            .iter()
            .any(|node| node.name == "direct")
    );
    assert!(admitted.dependencies.is_empty());
    assert!(!temp.path().join("state").exists());
    loaded
        .config
        .subscriptions
        .push(honk_config::subscription::Subscription {
            name: "offline".into(),
            url: format!(
                "http://{}/private-credential",
                listener.local_addr().unwrap()
            ),
            ..Default::default()
        });
    // A subscription that was never fetched is admitted without its nodes, as
    // the runtime would start it; the notice names neither the URL nor a path.
    let mut notices = Vec::new();
    let admitted = validate_with_data_dir(
        loaded,
        &active,
        Path::new(&active.global.data_dir),
        SourceLimits::default(),
        &mut notices,
    )
    .unwrap();
    assert!(admitted.dependencies.is_empty());
    let notice = notices
        .iter()
        .find(|notice| notice.code == "subscription-not-fetched")
        .unwrap();
    assert_eq!(notice.severity, honk_config::diagnostic::Severity::Warning);
    assert!(!format!("{notice:?}").contains("private-credential"));
    assert!(!temp.path().join("state").exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fs::read_to_string(&sources[0].path).unwrap(),
        sources[0].content.as_ref()
    );
}

#[test]
fn hosts_admission_charges_each_materialized_reference() {
    let temp = tempfile::tempdir().unwrap();
    let hosts = temp.path().join("hosts.rules");
    let body = "full:exact.test 192.0.2.1\n";
    fs::write(&hosts, body).unwrap();
    let loaded = fixture(
        temp.path(),
        &format!(
            "dns {{ use_host: '{}'\n use_host: '{}/./hosts.rules' }}",
            hosts.display(),
            temp.path().display()
        ),
    );
    let active = loaded.config.clone();
    let size = loaded
        .sources
        .iter()
        .map(|source| source.content.len())
        .sum::<usize>()
        + 2 * body.len();
    let exact = SourceLimits {
        max_bytes: size,
        max_sources: 3,
    };
    let admitted = admit_with_limits(loaded.clone(), &active, exact).unwrap();
    assert_eq!(
        admitted.dependencies,
        admitted
            .recapture_dependencies(&active, Path::new(&active.global.data_dir), exact, &[],)
            .unwrap()
    );
    let short = SourceLimits {
        max_bytes: size - 1,
        ..exact
    };
    assert_eq!(
        admit_with_limits(loaded.clone(), &active, short)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "config-byte-limit"
    );
    let short = SourceLimits {
        max_sources: 2,
        ..exact
    };
    assert_eq!(
        admit_with_limits(loaded.clone(), &active, short)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "config-source-limit"
    );
    fs::write(&hosts, "regexp:[ 192.0.2.1\n").unwrap();
    let error = admit(loaded.clone(), &active).err().unwrap();
    assert_eq!(error.diagnostic.code, "invalid-offline-dependency");
    fs::remove_file(&hosts).unwrap();
    assert_eq!(
        admit(loaded, &active).err().unwrap().diagnostic.code,
        "missing-offline-dependency"
    );
}

#[test]
fn unused_submissions_share_exact_materialization_byte_and_count_limits() {
    let temp = tempfile::tempdir().unwrap();
    let body = "full:exact.test 192.0.2.1\n";
    fs::write(temp.path().join("hosts.rules"), body).unwrap();
    let loaded = fixture(
        temp.path(),
        &format!(
            "dns {{ use_host: '{}/hosts.rules'\n use_host: '{}/./hosts.rules' }}",
            temp.path().display(),
            temp.path().display(),
        ),
    );
    let active = loaded.config.clone();
    let unused = "# submitted but not included\n";
    let submitted = [
        (
            loaded.sources[0].path.clone(),
            loaded.sources[0].content.clone(),
        ),
        (temp.path().join("unused.dae"), Arc::from(unused)),
    ];
    let exact = SourceLimits {
        max_bytes: loaded.sources[0].content.len() + unused.len() + 2 * body.len(),
        max_sources: 4,
    };
    let validate = |limits| {
        validate_for_coordinator(
            loaded.clone(),
            loaded.sources[0].path.parent(),
            &active,
            Path::new(&active.global.data_dir),
            limits,
            &mut Vec::new(),
            &[],
            None,
            &submitted,
        )
    };
    let admitted = validate(exact).unwrap();
    assert_eq!(
        admitted.dependencies,
        admitted
            .recapture_dependencies(&active, Path::new(&active.global.data_dir), exact, &[])
            .unwrap()
    );
    for (limits, code) in [
        (
            SourceLimits {
                max_bytes: exact.max_bytes - 1,
                ..exact
            },
            "config-byte-limit",
        ),
        (
            SourceLimits {
                max_sources: exact.max_sources - 1,
                ..exact
            },
            "config-source-limit",
        ),
    ] {
        assert_eq!(validate(limits).err().unwrap().diagnostic.code, code);
    }
}

#[test]
fn revalidation_binds_ordered_host_aliases_to_their_targets() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first.rules");
    let last = temp.path().join("last.rules");
    fs::write(&first, "full:shared.test 192.0.2.1\n").unwrap();
    fs::write(&last, "full:shared.test 192.0.2.2\n").unwrap();
    let first_reader = temp.path().join("first-reader");
    let last_reader = temp.path().join("last-reader");
    std::os::unix::fs::symlink(&first, &first_reader).unwrap();
    std::os::unix::fs::symlink(&last, &last_reader).unwrap();
    let loaded = fixture(
        temp.path(),
        &format!(
            "dns {{ use_host: '{}'\n use_host: '{}' }}",
            first_reader.display(),
            last_reader.display(),
        ),
    );
    let active = loaded.config.clone();
    let data_dir = Path::new(&active.global.data_dir);
    let admitted = admit(loaded, &active).unwrap();
    assert_eq!(
        admitted.dependencies,
        admitted
            .recapture_dependencies(&active, data_dir, SourceLimits::default(), &[])
            .unwrap()
    );
    fs::remove_file(&first_reader).unwrap();
    fs::remove_file(&last_reader).unwrap();
    std::os::unix::fs::symlink(&last, &first_reader).unwrap();
    std::os::unix::fs::symlink(&first, &last_reader).unwrap();
    assert_ne!(
        admitted.dependencies,
        admitted
            .recapture_dependencies(&active, data_dir, SourceLimits::default(), &[])
            .unwrap()
    );
}

// A minimal geoip.dat: one country code with `count` /24 networks, in the
// v2fly protobuf wire format the runtime reads.
fn geoip_dat(code: &str, count: u32) -> Vec<u8> {
    fn varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }
    fn delimited(tag: u8, payload: &[u8], out: &mut Vec<u8>) {
        out.push(tag << 3 | 2);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }
    let mut entry = Vec::new();
    delimited(1, code.as_bytes(), &mut entry);
    for index in 0..count {
        let mut cidr = Vec::new();
        delimited(1, &[10, (index >> 8) as u8, index as u8, 0], &mut cidr);
        cidr.push(2 << 3);
        varint(24, &mut cidr);
        delimited(2, &cidr, &mut entry);
    }
    let mut dat = Vec::new();
    delimited(1, &entry, &mut dat);
    dat
}

#[test]
fn geodata_assets_are_hashed_but_stay_outside_the_source_budget() {
    let temp = tempfile::tempdir().unwrap();
    // The fixture's routing has no geo rule; validation must need geoip.dat.
    fixture(temp.path(), "");
    let path = temp.path().join("config.dae");
    let text = fs::read_to_string(&path).unwrap().replace(
        "routing { fallback: direct }",
        "routing { dip(geoip: lab) -> direct\n fallback: direct }",
    );
    fs::write(&path, &text).unwrap();
    let loaded = Config::from_dae_file_with_sources(
        &path,
        &HashMap::new(),
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    let active = loaded.config.clone();
    let data_dir = PathBuf::from(&active.global.data_dir);
    fs::create_dir_all(&data_dir).unwrap();
    let dat = geoip_dat("lab", 2000);
    fs::write(data_dir.join("geoip.dat"), &dat).unwrap();
    let source_bytes = loaded
        .sources
        .iter()
        .map(|source| source.content.len())
        .sum::<usize>();
    assert!(dat.len() > source_bytes);
    // Exactly the sources fit: the asset is larger than the whole budget and must not count.
    let exact = SourceLimits {
        max_bytes: source_bytes,
        max_sources: 1,
    };
    let admitted = admit_with_limits(loaded.clone(), &active, exact).unwrap();
    let asset = admitted
        .dependencies
        .iter()
        .find(|dependency| dependency.asset)
        .expect("geoip.dat is a recorded dependency");
    assert_eq!(asset.bytes, dat.len());
    assert_eq!(asset.sha256, crate::configuration::digest(&dat));
    // The source budget itself still applies.
    let short = SourceLimits {
        max_bytes: source_bytes - 1,
        max_sources: 1,
    };
    assert_eq!(
        admit_with_limits(loaded, &active, short)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "config-byte-limit"
    );
}

#[test]
fn repeated_aliases_cannot_retain_bodies_beyond_byte_or_source_limits() {
    let temp = tempfile::tempdir().unwrap();
    let body = "full:alias.test 192.0.2.1\n";
    fs::write(temp.path().join("hosts.rules"), body).unwrap();
    let mut loaded = fixture(temp.path(), "");
    loaded.config.dns.hosts = (0..200)
        .map(|index| {
            format!(
                "{}/{}hosts.rules",
                temp.path().display(),
                "./".repeat(index)
            )
        })
        .collect();
    let source_bytes = loaded
        .sources
        .iter()
        .map(|source| source.content.len())
        .sum::<usize>();
    for (limits, expected_kind, retained_count) in [
        (
            SourceLimits {
                max_bytes: source_bytes + 3 * body.len(),
                max_sources: 32,
            },
            io::ErrorKind::FileTooLarge,
            3,
        ),
        (
            SourceLimits {
                max_bytes: source_bytes + 200 * body.len(),
                max_sources: 3,
            },
            io::ErrorKind::QuotaExceeded,
            2,
        ),
    ] {
        let mut capture = Capture::new(
            &loaded.sources,
            loaded.sources[0].path.parent(),
            &loaded.config,
            Path::new(&loaded.config.global.data_dir),
            limits,
            &[],
        )
        .unwrap();
        let mut retained_bytes = 0;
        let mut index = 0;
        let result = HostsSourceSet::load_captured(&loaded.config.dns, |path| {
            let reader = DependencyReader::Hosts(index, path.to_owned());
            index += 1;
            let text = capture.text(path, reader)?;
            retained_bytes += text.len();
            Ok::<_, io::Error>(text)
        });
        assert_eq!(result.err().unwrap().kind(), expected_kind);
        assert_eq!(retained_bytes, retained_count * body.len());
        assert!(retained_bytes <= limits.max_bytes - source_bytes);
    }
}

#[test]
fn external_hosts_require_active_authorization_including_symlink_targets() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let external = outside.path().join("private.rules");
    fs::write(&external, "full:private.test 192.0.2.2\n").unwrap();
    let alias = temp.path().join("inside.rules");
    std::os::unix::fs::symlink(&external, &alias).unwrap();
    let loaded = fixture(
        temp.path(),
        &format!("dns {{ use_host: '{}' }}", alias.display()),
    );
    let mut active = loaded.config.clone();
    active.dns.hosts.clear();
    let error = admit(loaded.clone(), &active).err().unwrap();
    assert_eq!(error.diagnostic.code, "offline-dependency-denied");
    assert!(!error.to_string().contains("private.rules"));
    assert!(error.diagnostic.span.is_none());
    active
        .dns
        .hosts
        .push(external.to_string_lossy().into_owned());
    let admitted = admit(loaded, &active).unwrap();
    assert_eq!(
        admitted.dependencies[0].path,
        fs::canonicalize(external).unwrap()
    );
}

#[test]
fn ech_is_bounded_and_inline_material_wins_without_opening_a_file() {
    let temp = tempfile::tempdir().unwrap();
    let mut loaded = fixture(
        temp.path(),
        "node { tls: 'trojan://credential@127.0.0.1:443#tls' }",
    );
    let ech = temp.path().join("private.ech");
    let tls = loaded.config.nodes[0].tls_mut().unwrap();
    tls.ech_config_path = Some(ech.to_string_lossy().into_owned());
    loaded.config.nodes[0].id = loaded.config.nodes[0].derive_id();
    let active = loaded.config.clone();
    assert_eq!(
        admit(loaded.clone(), &active)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "missing-offline-dependency"
    );
    fs::write(&ech, "not base64!!").unwrap();
    let error = admit(loaded.clone(), &active).err().unwrap();
    assert_eq!(error.diagnostic.code, "invalid-tls-config");
    assert!(!error.to_string().contains("credential"));
    assert!(!error.to_string().contains("private.ech"));
    fs::write(&ech, "AA==\n").unwrap();
    let admitted = admit(loaded.clone(), &active).unwrap();
    assert_eq!(admitted.dependencies[0].bytes, 5);
    assert_eq!(
        admitted.dependencies,
        admitted
            .recapture_dependencies(
                &active,
                Path::new(&active.global.data_dir),
                SourceLimits::default(),
                &[],
            )
            .unwrap()
    );
    fs::remove_file(&ech).unwrap();
    loaded.config.nodes[0].tls_mut().unwrap().ech_config = Some("AA==".into());
    loaded.config.nodes[0].id = loaded.config.nodes[0].derive_id();
    let admitted = admit(loaded, &active).unwrap();
    assert!(admitted.dependencies.is_empty());
    assert!(
        admitted
            .recapture_dependencies(
                &active,
                Path::new(&active.global.data_dir),
                SourceLimits::default(),
                &[],
            )
            .unwrap()
            .is_empty()
    );
}

fn cache_body(
    data_dir: &Path,
    subscription: &honk_config::subscription::Subscription,
    body: &str,
) -> crate::subscription::SubscriptionStore {
    fs::create_dir_all(data_dir).unwrap();
    let store = crate::subscription::SubscriptionStore::in_dir(data_dir);
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(store.store_content(subscription, body.into()))
        .unwrap();
    store
}

#[test]
fn cached_subscriptions_remain_inside_source_budgets() {
    let temp = tempfile::tempdir().unwrap();
    let mut loaded = fixture(temp.path(), "");
    let subscription = honk_config::subscription::Subscription {
        name: "bounded".into(),
        url: "https://example.invalid/nodes".into(),
        ..Default::default()
    };
    let body = "socks5://127.0.0.1:1080#cached";
    cache_body(
        Path::new(&loaded.config.global.data_dir),
        &subscription,
        body,
    );
    loaded.config.subscriptions.push(subscription);
    let exact = SourceLimits {
        max_sources: 2,
        max_bytes: loaded.sources[0].content.len() + body.len(),
    };
    let admitted = admit_with_limits(loaded.clone(), &loaded.config, exact).unwrap();
    assert!(
        admitted
            .config
            .nodes
            .iter()
            .any(|node| node.name == "cached")
    );
    assert_eq!(
        admitted.dependencies,
        admitted
            .recapture_dependencies(
                &loaded.config,
                Path::new(&loaded.config.global.data_dir),
                exact,
                &[],
            )
            .unwrap()
    );
    for (limits, code) in [
        (
            SourceLimits {
                max_sources: 1,
                ..exact
            },
            "config-source-limit",
        ),
        (
            SourceLimits {
                max_bytes: exact.max_bytes - 1,
                ..exact
            },
            "config-byte-limit",
        ),
    ] {
        assert_eq!(
            admit_with_limits(loaded.clone(), &loaded.config, limits)
                .err()
                .unwrap()
                .diagnostic
                .code,
            code,
        );
    }
}

#[test]
fn subscription_notices_name_the_file_that_declares_the_subscription() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("config.d")).unwrap();
    fs::write(
        temp.path().join("config.d/providers.dae"),
        "subscription {\n included: 'https://example.invalid/included'\n}\n",
    )
    .unwrap();
    let loaded = fixture(
        temp.path(),
        "include {\n 'config.d/*.dae'\n}\nsubscription {\n entry: 'https://example.invalid/entry'\n}\n",
    );
    let included = loaded
        .config
        .subscriptions
        .iter()
        .find(|subscription| subscription.name == "included")
        .unwrap();
    cache_body(
        Path::new(&loaded.config.global.data_dir),
        included,
        "socks5://127.0.0.1:1080#first\nsocks5://127.0.0.1:1080#duplicate\n",
    );
    let path_of = |notice: &DetailedDiagnostic| {
        notice.source.sources().metadata()[notice.source.index()]
            .path
            .clone()
    };
    let mut notices = Vec::new();
    validate_with_data_dir(
        loaded.clone(),
        &loaded.config,
        Path::new(&loaded.config.global.data_dir),
        SourceLimits::default(),
        &mut notices,
    )
    .unwrap();
    let duplicate = notices
        .iter()
        .find(|notice| notice.code == "duplicate-subscription-entry")
        .unwrap();
    assert_eq!(path_of(duplicate), Some(loaded.sources[1].path.clone()));
    assert_eq!((duplicate.line, duplicate.byte_column), (None, None));
    let unfetched = notices
        .iter()
        .find(|notice| notice.code == "subscription-not-fetched")
        .unwrap();
    assert_eq!(path_of(unfetched), Some(loaded.sources[0].path.clone()));
}

#[test]
fn an_invalid_included_subscription_names_its_file() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("config.d")).unwrap();
    fs::write(
        temp.path().join("config.d/providers.dae"),
        "subscription {\n included: 'ftp://example.invalid/nodes'\n}\n",
    )
    .unwrap();
    let loaded = fixture(temp.path(), "include {\n 'config.d/*.dae'\n}\n");
    let error = admit(loaded.clone(), &loaded.config).err().unwrap();
    assert_eq!(error.diagnostic.code, "invalid-config-value");
    let source = &error.diagnostic.source;
    assert_eq!(
        source.sources().metadata()[source.index()].path,
        Some(loaded.sources[1].path.clone())
    );
}

#[test]
fn cached_presence_and_rebased_active_semantics_are_both_required() {
    let temp = tempfile::tempdir().unwrap();
    let mut loaded = fixture(temp.path(), "");
    let subscription = honk_config::subscription::Subscription {
        name: "provider".into(),
        url: "https://example.invalid/private-token".into(),
        ..Default::default()
    };
    loaded.config.subscriptions.push(subscription.clone());
    let mut active = loaded.config.clone();
    active.nodes = parse_subscription_content_with_diagnostics(
        &subscription,
        "trojan://password@127.0.0.1:443#active",
        &mut Vec::new(),
    )
    .unwrap();
    active.nodes[0].tls_mut().unwrap().pin_sha256 = Some("invalid-pin".into());
    active.nodes[0].id = active.nodes[0].derive_id();
    loaded.config.subscriptions[0].id = uuid::Uuid::new_v4();
    let cache = cache_body(
        Path::new(&active.global.data_dir),
        &subscription,
        "socks5://127.0.0.1:1080#cached",
    );
    let cached_only = admit(loaded.clone(), &loaded.config).unwrap();
    assert!(
        cached_only
            .config
            .nodes
            .iter()
            .any(|node| node.name == "cached")
    );
    assert_eq!(
        admit(loaded.clone(), &active)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "invalid-tls-config"
    );
    active.nodes[0].tls_mut().unwrap().pin_sha256 = None;
    active.nodes[0].id = active.nodes[0].derive_id();
    let admitted = admit(loaded.clone(), &active).unwrap();
    assert!(
        admitted
            .config
            .nodes
            .iter()
            .any(|node| node.name == "active")
    );
    assert!(
        !admitted
            .config
            .nodes
            .iter()
            .any(|node| node.name == "cached")
    );
    assert_eq!(
        admitted.dependencies[0].path,
        Path::new(&active.global.data_dir).join(format!(
            "state/honk.db#subscription/{}",
            crate::subscription::SubscriptionStore::key(&subscription)
        ))
    );
    assert_eq!(
        admitted
            .recapture_dependencies(
                &active,
                Path::new(&active.global.data_dir),
                SourceLimits::default(),
                &[],
            )
            .unwrap(),
        admitted.dependencies,
        "unchanged cached input must survive subscription identity rebasing",
    );
    // Without the cache the subscription contributes no cached node; the
    // configuration is still admitted and the runtime's same-fetch node still
    // rebases onto it.
    cache.remove_body(&subscription);
    let admitted = admit(loaded, &active).unwrap();
    assert!(admitted.dependencies.is_empty());
    let names: Vec<_> = admitted
        .config
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect();
    assert!(names.contains(&"active"));
    assert!(!names.contains(&"cached"));
}

#[test]
fn revalidation_detects_a_new_higher_priority_dependency() {
    let working = std::env::current_dir().unwrap();
    let temp = tempfile::tempdir_in(&working).unwrap();
    let mut loaded = fixture(temp.path(), "");
    let data_dir = PathBuf::from(&loaded.config.global.data_dir);
    fs::create_dir(&data_dir).unwrap();
    let lower = temp.path().join("hosts.rules");
    fs::write(&lower, "full:old.test 192.0.2.1\n").unwrap();
    let relative = lower.strip_prefix(&working).unwrap();
    let higher = data_dir.join(relative);
    loaded
        .config
        .dns
        .hosts
        .push(relative.to_string_lossy().into_owned());
    let active = loaded.config.clone();
    let old = admit(loaded, &active).unwrap();
    fs::create_dir_all(higher.parent().unwrap()).unwrap();
    fs::write(&higher, "full:new.test 192.0.2.2\n").unwrap();
    let dependencies = old
        .recapture_dependencies(&active, &data_dir, SourceLimits::default(), &[])
        .unwrap();
    assert_ne!(old.dependencies, dependencies);
    assert_eq!(dependencies[0].path, fs::canonicalize(higher).unwrap());
}

#[test]
fn geodata_overlay_compiles_and_retains_verified_bytes_instead_of_disk() {
    let directory = tempfile::tempdir().unwrap();
    let mut loaded = fixture(directory.path(), "");
    loaded.config.routing = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
        "routing { dip(geoip: lab) -> block\n fallback: direct }",
        &mut Vec::new(),
    )
    .unwrap()
    .routing;
    let active = loaded.config.clone();
    let data_dir = Path::new(&active.global.data_dir);
    fs::create_dir_all(data_dir).unwrap();
    let path = data_dir.join("geoip.dat");
    fs::write(&path, b"invalid live disk").unwrap();
    let requirements = GeoRequirements::for_traffic(&active.routing.rules);
    let bytes = geoip_dat("lab", 2);
    let expected = crate::routing::GeoAssetSnapshot {
        kind: "geoip",
        path: Some(path),
        sha256: crate::configuration::digest(&bytes),
        size_bytes: bytes.len() as u64,
        modified_at: None,
    };
    let geo =
        GeoSourceSet::from_assets(&requirements, vec![(expected.clone(), bytes.into())]).unwrap();
    assert!(admit(loaded.clone(), &active).is_err());
    let admitted = validate_for_coordinator(
        loaded.clone(),
        loaded.sources[0].path.parent(),
        &active,
        data_dir,
        SourceLimits::default(),
        &mut Vec::new(),
        &[],
        Some(&geo),
        &[],
    )
    .unwrap();
    assert_eq!(admitted.dependencies[0].sha256, expected.sha256);
    assert_eq!(
        admitted.dependencies,
        admitted
            .recapture_dependencies(&active, data_dir, SourceLimits::default(), &[])
            .unwrap()
    );
    assert_eq!(
        admitted.geo_sources.unwrap().snapshots(&requirements),
        vec![expected]
    );
}

#[test]
fn a_stored_body_over_the_budget_is_refused_before_it_is_read() {
    let temp = tempfile::tempdir().unwrap();
    let loaded = fixture(temp.path(), "");
    let mut capture = Capture::new(
        &loaded.sources,
        loaded.sources[0].path.parent(),
        &loaded.config,
        Path::new(&loaded.config.global.data_dir),
        SourceLimits::default(),
        &[],
    )
    .unwrap();
    let error = capture
        .stored(
            temp.path().join("state/honk.db#subscription/large"),
            9 * 1024 * 1024,
            DependencyReader::Subscription(0),
            || panic!("the body was read before the budget check"),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
}

#[test]
fn a_sized_read_keeps_whatever_the_file_holds_when_its_length_changed() {
    let bytes = b"geodata bytes";
    assert_eq!(&*read_sized(&bytes[..], bytes.len()).unwrap(), bytes);
    assert_eq!(&*read_sized(&bytes[..], 4).unwrap(), bytes);
    assert_eq!(&*read_sized(&bytes[..], 64).unwrap(), bytes);
    assert!(read_sized(&[][..], 0).unwrap().is_empty());
}
