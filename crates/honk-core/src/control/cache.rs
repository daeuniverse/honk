use super::*;

impl ControlPlane {
    /// Open the persistent cache database (sing-box `cache_file`), wire
    /// selector-choice persistence into the group manager, and restore
    /// persisted choices. An existing cache relative to the original config
    /// directory is retained during the data-directory cutover. No-op when
    /// `experimental.cache_file` is disabled or the database cannot be opened.
    /// Called once from `run()`.
    pub async fn init_cache_db(&mut self, legacy_config_dir: Option<&Path>) {
        let cache_cfg = self.config.read().await.experimental.cache_file.clone();
        let Some(db) = crate::cachedb::CacheDb::open_with_config_dir(&cache_cfg, legacy_config_dir)
        else {
            return;
        };
        let db = Arc::new(db);

        // Restore persisted selector choices before wiring the persist
        // callback so restoration does not rewrite the same values.
        {
            let config = self.config.read().await;
            for group in &config.groups {
                if group.policy == GroupPolicy::Selector
                    && let Some(node) = db.load_selector_choice(&group.name)
                {
                    info!("cache.db: restored selector '{}' = '{}'", group.name, node);
                    self.group_manager
                        .read()
                        .set_selector_choice(&group.name, &node);
                }
            }
        }

        let db_cb = db.clone();
        self.group_manager
            .read()
            .set_persist_callback(Some(Arc::new(move |group, node| {
                db_cb.save_selector_choice(group, node);
            })));

        // Delay-history persistence (sing-box URLTest history storage
        // parity): restore the last real delay sample per node so URLTest
        // groups don't start cold after a restart, then mirror fresh
        // samples back every minute. Liveness is NOT restored — probes
        // re-decide that; stale entries (>24h) are dropped on load.
        {
            const DELAY_SAMPLE_MAX_AGE_SECS: u64 = 24 * 3600;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let samples = db.load_delay_samples(now_unix, DELAY_SAMPLE_MAX_AGE_SECS);
            // cache.db keys delay samples by node name (format unchanged);
            // resolve them onto this generation's NodeIds — samples for
            // nodes no longer configured are dropped.
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
                info!("cache.db: restored {} persisted delay sample(s)", restored);
            }
            let db_delay = db.clone();
            let alive_for_delay = self.alive_set.clone();
            let config_for_delay = self.config.clone();
            let delay_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.tick().await; // first snapshot after one period
                loop {
                    let names: std::collections::HashMap<uuid::Uuid, String> = config_for_delay
                        .read()
                        .await
                        .nodes
                        .iter()
                        .map(|n| (n.id, n.name.clone()))
                        .collect();
                    for (node_id, latency, at) in alive_for_delay.latency_snapshot() {
                        let Some(name) = names.get(&node_id) else {
                            continue;
                        };
                        let measured_at = at
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        db_delay.save_delay_sample(name, latency.as_millis() as u64, measured_at);
                    }
                    interval.tick().await;
                }
            });
            self.background_tasks.lock().await.push(delay_task);
        }

        // store_dns: restore persisted DNS answers into the shared DNS
        // cache, then mirror future answers into cache.db through a
        // background batch writer (sing-box SaveDNSCacheAsync). Restoring
        // runs before the persister is installed so restored entries are
        // not immediately re-persisted.
        if cache_cfg.store_dns {
            let dns_cache = self.dns_controller.cache().await;
            let persister = crate::dns::persist::DnsCachePersister::spawn(db.clone());
            let policy = self.dns_controller.forwarder().policy_id();
            match persister.restore_cache(&dns_cache, policy).await {
                Ok(restored) if restored > 0 => {
                    info!("cache.db: restored {} persisted DNS answer(s)", restored);
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "cache.db DNS restore failed"),
            }
            dns_cache.lock().await.set_persister(Some(persister));
        }

        self.cache_db = Some(db);
    }

    /// Shared handle to the persistent cache database (clash API, etc.).
    pub fn cache_db(&self) -> Option<Arc<crate::cachedb::CacheDb>> {
        self.cache_db.clone()
    }
}
