//! Startup bootstrap of the state db: opening it, and claiming it once the
//! instance lock is held.

use std::path::PathBuf;
use std::sync::Arc;

use honk_config::Config;
use tracing::warn;

use crate::{Cli, ConfigStore, degradations, state, subscription};

/// Opens the state db in file mode; db mode opened it with its revisions.
/// Returns `(db, reset)`: `reset` asks for a corrupt, non-strict db to be
/// moved aside once the instance lock is held.
///
/// Unless the db is strict, a db that is unavailable, unsafe or locked by
/// `admin reset` leaves honk running without persistence; a newer schema or a
/// foreign file still refuses startup, because only that binary can use it.
pub(crate) fn open_state_db(
    cli: &Cli,
    config: &Config,
    data_dir: &std::path::Path,
    degradations: &degradations::Degradations,
) -> anyhow::Result<(Option<Arc<state::StateDb>>, bool)> {
    let strict = cli.store == ConfigStore::Db || config.experimental.native_api.password_auth;
    if cli.store == ConfigStore::Db
        || !(config.experimental.cache_file.stores_selections()
            || config.global.store_subscribe
            || config.experimental.native_api.enabled
            || config.experimental.native_api.password_auth)
    {
        return Ok((None, false));
    }
    match state::StateDb::open(data_dir) {
        Ok(db) => Ok((Some(Arc::new(db)), false)),
        Err(state::StateError::Corrupt) if !strict => {
            warn!("state database is corrupt; it is moved aside once the instance lock is held");
            Ok((None, true))
        }
        Err(
            error @ (state::StateError::Unavailable
            | state::StateError::Unsafe(_)
            | state::StateError::Locked),
        ) if !strict => {
            warn!(%error, "continuing without persistence");
            persistence_lost(data_dir, degradations, error);
            Ok((None, false))
        }
        Err(error) => Err(anyhow::anyhow!("state database: {error}")),
    }
}

/// Moves a corrupt, non-strict state db aside; any failure, including another
/// process still holding the db, leaves honk running without persistence.
pub(crate) fn reset_non_strict(
    data_dir: &std::path::Path,
    degradations: &degradations::Degradations,
) -> Option<Arc<state::StateDb>> {
    // `Ok(None)`: an earlier corrupt copy blocks the move, so the db stays corrupt.
    let error = match state::reset_corrupt(data_dir) {
        Ok(Some(db)) => return Some(Arc::new(db)),
        Ok(None) => state::StateError::Corrupt,
        Err(error) => {
            warn!(%error, "state database could not be reset; continuing without persistence");
            error
        }
    };
    persistence_lost(data_dir, degradations, error);
    None
}

fn persistence_lost(
    data_dir: &std::path::Path,
    degradations: &degradations::Degradations,
    error: state::StateError,
) {
    let rule = match error {
        state::StateError::Unsafe(refusal) => {
            let path = data_dir.join(refusal.target.relative_path());
            warn!(
                path = %path.display(),
                rule = refusal.rule.as_str(),
                fix = %refusal.fix(&path),
                "state database path is unsafe"
            );
            Some(refusal.rule.as_str())
        }
        _ => None,
    };
    degradations.set_with_rule(
        degradations::Component::Persistence,
        degradations::Issue {
            code: "persistence_unavailable",
            message: "The state database is unavailable; runtime state is not kept across restarts.",
            reason: error.reason(),
        },
        rule,
    );
}

/// The state db and subscription store for this run.
pub(crate) struct ClaimedState {
    pub(crate) state_db: Option<Arc<state::StateDb>>,
    pub(crate) subscriptions: Option<subscription::SubscriptionStore>,
}

/// Startup changes to the state db, made with the instance lock held: the
/// reset of a corrupt non-strict db, clearing disabled owners' tables, and the
/// legacy `.sub` import and removal. The previous instance has exited, so a
/// legacy body it wrote last is copied before its store is removed.
pub(crate) fn claim_state(
    state_db: Option<Arc<state::StateDb>>,
    reset: bool,
    config: &Config,
    data_dir: &std::path::Path,
    legacy_roots: impl IntoIterator<Item = PathBuf>,
    degradations: &degradations::Degradations,
) -> ClaimedState {
    let state_db = if reset {
        reset_non_strict(data_dir, degradations)
    } else {
        state_db
    };
    if let Some(state) = state_db.as_ref() {
        let experimental = &config.experimental;
        let owners = state::ActiveOwners {
            cache: experimental.cache_file.stores_selections(),
            dns: experimental.cache_file.stores_dns(),
            clash: experimental.cache_file.stores_mode()
                && cfg!(feature = "clash-api")
                && !(cfg!(feature = "native-api") && experimental.native_api.enabled)
                && !experimental.clash_api.external_controller.is_empty(),
            subscriptions: config.global.store_subscribe,
        };
        if let Err(error) = state::clear_inactive(state, owners) {
            warn!(%error, "state database: clearing tables of disabled owners failed");
        }
    }
    let subscriptions = match state_db.as_ref().filter(|_| config.global.store_subscribe) {
        Some(state) => {
            if let Some(legacy) = subscription::LegacySubscriptionStore::import(
                state,
                legacy_roots,
                &config.subscriptions,
            ) {
                legacy.remove();
            }
            Some(subscription::SubscriptionStore::new(Arc::clone(state)))
        }
        None => {
            if config.global.store_subscribe {
                warn!("Subscription store unavailable; continuing without persistence");
            }
            None
        }
    };
    ClaimedState {
        state_db,
        subscriptions,
    }
}

#[cfg(test)]
mod state_claim_tests {
    use std::path::PathBuf;

    use clap::Parser as _;

    fn legacy_store(
        root: &std::path::Path,
        subscriptions: &[&honk_config::subscription::Subscription],
    ) {
        use std::os::unix::fs::PermissionsExt as _;

        if !root.exists() {
            std::fs::create_dir(root).unwrap();
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for sub in subscriptions {
            let path = root.join(crate::subscription::SubscriptionStore::key(sub));
            std::fs::write(&path, format!("socks5://127.0.0.1:1080#{}", sub.url)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn subscription(name: &str) -> honk_config::subscription::Subscription {
        honk_config::subscription::Subscription {
            url: format!("https://example.invalid/{name}"),
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_successor_without_the_instance_lock_leaves_the_state_alone() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let lock_path = directory.path().join("honk-core.lock");
        let _held = nix::fcntl::Flock::lock(
            std::fs::File::create(&lock_path).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .unwrap();
        crate::TEST_INSTANCE_LOCK.with(|path| *path.borrow_mut() = Some(lock_path.clone()));

        // One data directory without a db, and one whose db and legacy store
        // belong to the running instance.
        let empty = directory.path().join("empty");
        let running = directory.path().join("running");
        for data_dir in [&empty, &running] {
            std::fs::create_dir(data_dir).unwrap();
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let sub = subscription("kept");
        legacy_store(&running.join(".sub"), &[&sub]);
        drop(crate::state::StateDb::open(&running).unwrap());
        let snapshot = |data_dir: &std::path::Path| {
            let mut entries: Vec<_> = walk(data_dir);
            entries.sort();
            entries
        };
        let before = snapshot(&running);

        for data_dir in [&empty, &running] {
            let config = directory.path().join(format!(
                "{}.dae",
                data_dir.file_name().unwrap().to_string_lossy()
            ));
            std::fs::write(
                &config,
                format!(
                    "global {{\n data_dir: '{}'\n store_subscribe: true\n}}\nsubscription {{\n '{}'\n}}\n",
                    data_dir.display(),
                    sub.url
                ),
            )
            .unwrap();
            let cli = crate::Cli::parse_from([
                "honk-core",
                "--mock-ebpf",
                "-c",
                config.to_str().unwrap(),
            ]);
            let error = crate::run(cli).await.unwrap_err();
            assert!(error.to_string().contains("refusing to start"), "{error:#}");
        }
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
        assert_eq!(snapshot(&running), before);
        crate::TEST_INSTANCE_LOCK.with(|path| *path.borrow_mut() = None);
    }

    fn walk(root: &std::path::Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                entries.extend(walk(&entry.path()));
            }
            entries.push((entry.path(), metadata.len(), metadata.modified().unwrap()));
        }
        entries
    }

    #[test]
    fn a_reset_state_db_backs_the_subscription_store() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join(crate::state::STATE_DIR);
        std::fs::create_dir(&state_dir).unwrap();
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = state_dir.join(crate::state::DB_FILE);
        std::fs::write(&file, vec![0x5a; 8192]).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cli = crate::Cli::parse_from(["honk-core"]);
        let mut config = honk_config::Config::default();
        config.global.store_subscribe = true;

        let degradations = crate::degradations::Degradations::default();
        let (db, reset) =
            super::open_state_db(&cli, &config, directory.path(), &degradations).unwrap();
        assert!(db.is_none() && reset);
        let claimed = super::claim_state(
            db,
            reset,
            &config,
            directory.path(),
            [directory.path().join(".sub")],
            &degradations,
        );
        assert!(claimed.state_db.is_some());
        assert!(
            degradations.snapshot().is_empty(),
            "a successful reset degrades nothing"
        );
        assert!(claimed.subscriptions.is_some());
        assert!(state_dir.join("honk.db.corrupt").exists());
    }
}
