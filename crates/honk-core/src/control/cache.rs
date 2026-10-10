use super::*;
use crate::dns::persist::unix_now;
use crate::state::StateDb;
use crate::state::cache::{
    CacheDb, DELAY_SAMPLE_MAX_AGE_SECS, Live, Maintenance, Missing, TickOwners, maintenance_tick,
};

/// The state db maintenance tick, every 60 s while the cache is open.
#[derive(Default)]
pub(super) struct StateTick {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl StateTick {
    /// Stops at the next wait; a maintenance write in flight finishes first.
    pub(super) async fn stop_and_join(&mut self) -> anyhow::Result<()> {
        self.stop.take();
        let Some(handle) = self.task.as_mut() else {
            return Ok(());
        };
        let result = match tokio::time::timeout(super::lifecycle::STAGE_TIMEOUT, &mut *handle).await
        {
            Ok(result) => result,
            Err(_) => {
                warn!("state maintenance exceeded its stop deadline; waiting for blocking work");
                handle.await
            }
        };
        self.task.take();
        result.map_err(anyhow::Error::from)
    }
}

impl Drop for StateTick {
    fn drop(&mut self) {
        // The outer task retains its blocking write until it finishes.
        self.stop.take();
    }
}

impl ControlPlane {
    /// Open the cache tables of the state database, import a legacy
    /// `cache.db`, restore and persist Selector choices and delay samples, and
    /// start the maintenance tick. `cache_file.enabled: true` also keeps the
    /// Clash mode and, with `store_dns`, DNS answers; `enabled: false` starts
    /// only the tick, for subscription bodies. No-op when there is no state
    /// database. Called once from `run()`, with the instance lock held.
    pub async fn init_cache_db(
        &mut self,
        state: Option<Arc<StateDb>>,
        legacy: Option<crate::state::import::LegacyCache>,
    ) {
        let cache_cfg = self.config.read().await.experimental.cache_file.clone();
        let Some(state) = state else {
            return;
        };
        self.state_db = Some(Arc::clone(&state));
        if !cache_cfg.stores_selections() {
            self.start_state_tick(state, None);
            return;
        }
        if let Some(legacy) = legacy {
            let scope = {
                let config = self.config.read().await;
                crate::state::import::ImportScope {
                    selector_groups: config
                        .groups
                        .iter()
                        .filter(|group| group.policy == GroupPolicy::Selector)
                        .map(|group| group.name.clone())
                        .collect(),
                    nodes: config.nodes.iter().map(|node| node.name.clone()).collect(),
                }
            };
            crate::state::import::import_cache_db(&state, &legacy, &scope);
        }
        let db = match CacheDb::open(Arc::clone(&state)) {
            Ok(db) => Arc::new(db),
            Err(error) => {
                warn!(%error, "state cache unavailable; continuing without persistence");
                self.degradations.set(
                    crate::degradations::Component::StateCache,
                    crate::degradations::Issue {
                        code: "state_cache_unavailable",
                        message: "The state cache could not be opened; Selector choices and delay history are not kept across restarts.",
                        reason: error.reason(),
                    },
                );
                self.start_state_tick(state, None);
                return;
            }
        };

        // Restore persisted selector choices before wiring the persist
        // callback so restoration does not rewrite the same values.
        {
            let groups = self.config.read().await.groups.clone();
            let group_manager = self.group_manager.read().clone();
            for group in groups
                .iter()
                .filter(|group| group.policy == GroupPolicy::Selector)
            {
                for network in [
                    honk_outbound::group::SelectionNetwork::Tcp,
                    honk_outbound::group::SelectionNetwork::Udp,
                ] {
                    if let Some(Ok(member)) = db.load_network_selector(&group.name, network)
                        && let Ok(update) = group_manager.publish_selector_choice(
                            &group.name,
                            &member,
                            network.into(),
                        )
                    {
                        update.run_callbacks_without_interrupt();
                    }
                }
            }
        }

        let db_cb = db.clone();
        self.group_manager
            .read()
            .set_persist_callback(Some(Arc::new(move |group, network, member| {
                db_cb.save_network_selector(group, network, member);
            })));

        // Delay-history persistence (sing-box URLTest history storage
        // parity): restore the last real delay sample per node so URLTest
        // groups don't start cold after a restart, then mirror fresh
        // samples back every minute from the maintenance tick. Liveness is
        // NOT restored — probes re-decide that; stale entries (>24h) are
        // dropped on load.
        {
            let samples = db.load_delay_samples(unix_now(), DELAY_SAMPLE_MAX_AGE_SECS);
            // Delay samples are keyed by node name; resolve them onto this
            // generation's NodeIds — samples for nodes no longer configured
            // are dropped.
            let id_by_name: std::collections::HashMap<String, uuid::Uuid> = {
                let config = self.config.read().await;
                config
                    .nodes
                    .iter()
                    .map(|n| (n.name.clone(), n.id))
                    .collect()
            };
            let mut restored = 0usize;
            for (node, delay_ms, measured_at) in samples {
                let Some(node_id) = id_by_name.get(node.as_str()).copied() else {
                    continue;
                };
                self.alive_set.restore_latency(
                    node_id,
                    std::time::Duration::from_millis(delay_ms),
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(measured_at),
                );
                restored += 1;
            }
            if restored > 0 {
                info!("state db: restored {} persisted delay sample(s)", restored);
            }
        }

        // store_dns: restore persisted DNS answers into the shared DNS
        // cache, then mirror future answers into the state db through a
        // background batch writer (sing-box SaveDNSCacheAsync). Restoring
        // runs before the persister is installed so restored entries are
        // not immediately re-persisted.
        if cache_cfg.stores_dns() {
            let dns_cache = self.dns_controller.cache().await;
            let persister = crate::dns::persist::DnsCachePersister::spawn(db.clone());
            let policy = self.dns_controller.forwarder().policy_id();
            match persister.restore_cache(&dns_cache, policy).await {
                Ok(restored) if restored > 0 => {
                    info!("state db: restored {} persisted DNS answer(s)", restored);
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "state db DNS restore failed"),
            }
            dns_cache.lock().await.set_persister(Some(persister));
        }
        // Startup prune, after restore: only the age and expiry rules.
        if let Err(error) = db.maintain(Maintenance {
            delay_cutoff: unix_now().saturating_sub(DELAY_SAMPLE_MAX_AGE_SECS),
            dns_expired_at: cache_cfg.stores_dns().then(unix_now),
            ..Maintenance::default()
        }) {
            warn!(%error, "state db startup prune failed");
        }
        self.start_state_tick(state, Some(Arc::clone(&db)));

        self.mode_db = cache_cfg.stores_mode().then(|| Arc::clone(&db));
        self.cache_db = Some(db);
    }

    fn start_state_tick(&mut self, state: Arc<StateDb>, db: Option<Arc<CacheDb>>) {
        let alive = self.alive_set.clone();
        let config = self.config.clone();
        let (stop_tx, mut stop) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let mut missing = Missing::default();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                let (live, owners, names) = {
                    let config = config.read().await;
                    (
                        Live::of(&config),
                        TickOwners {
                            store_dns: config.experimental.cache_file.stores_dns(),
                            store_subscribe: config.global.store_subscribe,
                        },
                        config
                            .nodes
                            .iter()
                            .map(|n| (n.id, n.name.clone()))
                            .collect::<std::collections::HashMap<uuid::Uuid, String>>(),
                    )
                };
                let samples = if db.is_some() {
                    alive
                        .latency_snapshot()
                        .into_iter()
                        .filter_map(|(node_id, latency, at)| {
                            let measured_at = at
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            Some((
                                names.get(&node_id)?.clone(),
                                latency.as_millis() as u64,
                                measured_at,
                            ))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let (state, db) = (Arc::clone(&state), db.clone());
                missing = tokio::task::spawn_blocking(move || {
                    maintenance_tick(
                        &state,
                        db.as_deref(),
                        &live,
                        samples,
                        &mut missing,
                        owners,
                        unix_now(),
                    );
                    missing
                })
                .await
                .unwrap_or_default();
                tokio::select! {
                    _ = &mut stop => break,
                    _ = interval.tick() => {}
                }
            }
        });
        self.state_tick.stop = Some(stop_tx);
        self.state_tick.task = Some(task);
    }

    /// The state database, when `init_cache_db` had one.
    #[cfg(feature = "native-api")]
    pub(crate) fn state_db(&self) -> Option<Arc<StateDb>> {
        self.state_db.clone()
    }

    /// Shared handle to the persistent cache database (clash API, etc.).
    pub fn cache_db(&self) -> Option<Arc<crate::state::cache::CacheDb>> {
        self.cache_db.clone()
    }

    /// The cache database when it also keeps the Clash mode and GLOBAL selection.
    pub fn mode_db(&self) -> Option<Arc<crate::state::cache::CacheDb>> {
        self.mode_db.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::support::{canonical_socks5, control_plane};
    use honk_outbound::alive::{IpVersion, ProbeDomain};

    #[tokio::test(start_paused = true)]
    async fn blocking_tick_survives_cancelled_join_and_owner_drop() {
        for drop_owner in [false, true] {
            let (release, blocked) = std::sync::mpsc::channel();
            let (entered, started) = tokio::sync::oneshot::channel();
            let (finished, completion) = tokio::sync::oneshot::channel();
            let (stop, mut stopped) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                tokio::task::spawn_blocking(move || {
                    entered.send(()).unwrap();
                    blocked.recv().unwrap();
                })
                .await
                .unwrap();
                let _ = (&mut stopped).await;
                finished.send(()).unwrap();
            });
            let mut tick = StateTick {
                stop: Some(stop),
                task: Some(task),
            };
            started.await.unwrap();
            {
                let waiting = tick.stop_and_join();
                tokio::pin!(waiting);
                assert!(futures::poll!(&mut waiting).is_pending());
                tokio::time::advance(Duration::from_secs(11)).await;
                assert!(futures::poll!(&mut waiting).is_pending());
            }
            assert!(tick.task.is_some());
            if drop_owner {
                drop(tick);
            } else {
                let waiting = tick.stop_and_join();
                tokio::pin!(waiting);
                assert!(futures::poll!(&mut waiting).is_pending());
                release.send(()).unwrap();
                waiting.await.unwrap();
                completion.await.unwrap();
                continue;
            }
            release.send(()).unwrap();
            completion.await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_default_config_keeps_the_selection_across_a_restart() {
        let directory = tempfile::tempdir().unwrap();
        let state = Arc::new(StateDb::open(directory.path()).unwrap());
        let config = |members: &[(&str, u16)]| {
            let mut config = Config::default();
            config.ensure_builtin_nodes();
            let nodes: Vec<_> = members
                .iter()
                .map(|&(name, port)| canonical_socks5(name, "127.0.0.1", port, None))
                .collect();
            config.groups = vec![Group {
                name: "proxy".into(),
                nodes: nodes.iter().map(|node| node.id).collect(),
                policy: GroupPolicy::Selector,
                ..Default::default()
            }];
            config.nodes.extend(nodes);
            config
        };
        let restart = |config| {
            let state = Arc::clone(&state);
            async move {
                let mut plane = control_plane(config);
                plane.init_cache_db(Some(state), None).await;
                plane
            }
        };
        // A real restart comes after the writer's 100 ms flush.
        let stop = |plane: ControlPlane| {
            if let Some(db) = plane.cache_db() {
                db.maintain(Maintenance::default()).unwrap();
            }
        };
        let selected = |plane: &ControlPlane| {
            plane
                .group_manager
                .read()
                .select_node("proxy")
                .map(|node| node.name.clone())
        };

        let plane = restart(config(&[("a", 9), ("b", 10)])).await;
        plane
            .group_manager
            .read()
            .set_selector_choice("proxy", "b", honk_outbound::group::SelectorNetworks::Both)
            .unwrap();
        stop(plane);

        let plane = restart(config(&[("a", 9), ("b", 10)])).await;
        assert_eq!(selected(&plane).as_deref(), Some("b"));
        stop(plane);

        let plane = restart(config(&[("a", 9), ("c", 11)])).await;
        assert_eq!(selected(&plane).as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn a_state_cache_that_cannot_open_is_reported() {
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.experimental.cache_file.enabled = Some(true);
        let directory = tempfile::tempdir().unwrap();
        let state = Arc::new(StateDb::open(directory.path()).unwrap());
        // A new inode under the same name fails the identity check.
        let file = directory
            .path()
            .join(crate::state::STATE_DIR)
            .join(crate::state::DB_FILE);
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, b"").unwrap();
        let mut plane = control_plane(config);
        plane.init_cache_db(Some(state), None).await;
        assert!(plane.cache_db().is_none());
        assert!(
            plane
                .degradations
                .get(crate::degradations::Component::StateCache)
                .is_some()
        );
    }

    #[cfg(feature = "clash-api")]
    #[tokio::test]
    async fn a_cached_clash_mode_is_restored_only_when_enabled_explicitly() {
        let directory = tempfile::tempdir().unwrap();
        let state = Arc::new(StateDb::open(directory.path()).unwrap());
        CacheDb::open(Arc::clone(&state))
            .unwrap()
            .save_clash_mode("Global");
        for (enabled, mode) in [(None, "Direct"), (Some(true), "Global")] {
            let mut config = Config::default();
            config.ensure_builtin_nodes();
            config.experimental.cache_file.enabled = enabled;
            let mut plane = control_plane(config);
            plane.init_cache_db(Some(Arc::clone(&state)), None).await;
            assert!(plane.cache_db().is_some());
            assert_eq!(
                crate::startup_clash_mode(plane.mode_db().as_deref(), "Direct"),
                mode
            );
        }
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn shutdown_waits_for_a_blocked_maintenance_write() {
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        config.global.store_subscribe = true;
        let directory = tempfile::tempdir().unwrap();
        let state = Arc::new(StateDb::open(directory.path()).unwrap());
        let connection = state.strict();
        let mut plane = control_plane(config);
        plane.init_cache_db(Some(Arc::clone(&state)), None).await;
        // Let the first tick reach its maintenance write, which waits on `connection`.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            tokio::time::timeout(Duration::from_secs(11), plane.state_tick.stop_and_join(),)
                .await
                .is_err(),
            "shutdown finished while a maintenance write was in flight"
        );
        assert!(plane.state_tick.task.is_some());
        drop(connection);
        plane.state_tick.stop_and_join().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn startup_failure_and_drop_stop_delay_persistence() -> anyhow::Result<()> {
        for fail_startup in [false, true] {
            let directory = tempfile::tempdir()?;
            let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
            let node = canonical_socks5("cache-peer", "127.0.0.1", 9, None);
            let node_id = node.id;
            let mut config = Config::default();
            config.ensure_builtin_nodes();
            config.nodes.push(node);
            config.dns.bind = format!("tcp://{}", occupied.local_addr()?);
            config.experimental.cache_file.enabled = Some(true);
            let state = Arc::new(crate::state::StateDb::open(directory.path())?);
            let mut plane = control_plane(config);
            plane.init_cache_db(Some(state), None).await;
            let db = plane.cache_db().unwrap();
            let alive = plane.alive_set();
            let record = |delay| {
                alive.record_probe_latency(
                    node_id,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                    Duration::from_millis(delay),
                );
            };
            let persisted = || {
                db.load_delay_samples(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    24 * 3600,
                )
                .into_iter()
                .find(|(name, _, _)| name == "cache-peer")
                .map(|(_, delay, _)| delay)
            };
            record(13);
            tokio::time::advance(Duration::from_secs(60)).await;
            tokio::time::timeout(Duration::from_secs(1), async {
                while persisted() != Some(13) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await?;
            if fail_startup {
                plane.run().await.expect_err("occupied DNS listener");
            } else {
                drop(plane);
            }
            record(29);
            tokio::time::advance(Duration::from_secs(120)).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert_eq!(
                persisted(),
                Some(13),
                "stopped cache writer must not snapshot again"
            );
        }
        Ok(())
    }
}
