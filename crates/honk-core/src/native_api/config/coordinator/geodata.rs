use super::*;
use crate::configuration::{DependencyReader, DependencySnapshot, digest};
use crate::download_route::Outbounds;
use crate::native_api::config_write::{SourceFile, StagedFile};
use crate::native_api::geodata::{self, GeoUpdatePlan};
use crate::native_api::operations::OperationResult;
use crate::native_api::store::Pin;
use crate::routing::{GeoAssetSnapshot, GeoRequirements, GeoSourceSet};

#[derive(Clone, Copy, serde::Serialize)]
struct AssetWrite {
    kind: &'static str,
    written: Option<bool>,
    durability_confirmed: Option<bool>,
}

struct DownloadedAsset {
    original: GeoAssetSnapshot,
    bytes: Arc<[u8]>,
    unchanged: bool,
}

struct StagedAsset {
    snapshot: GeoAssetSnapshot,
    bytes: Arc<[u8]>,
    staged: StagedFile,
}

/// A download identical to the loaded file, which stays in place unwritten.
struct KeptAsset {
    snapshot: GeoAssetSnapshot,
    bytes: Arc<[u8]>,
    file: SourceFile,
}

struct InstalledAsset {
    snapshot: GeoAssetSnapshot,
    installed: SourceFile,
    receipt: AssetWrite,
}

struct PreparedGeodata {
    activation: ActivationRequest,
    assets: Vec<InstalledAsset>,
}

fn failure(
    stage: &'static str,
    writes: impl IntoIterator<Item = impl std::borrow::Borrow<AssetWrite>>,
) -> Value {
    let mut writes: Vec<AssetWrite> = writes.into_iter().map(|write| *write.borrow()).collect();
    writes.sort_by_key(|write| write.kind != "geosite");
    json!({"stage":stage,"assets":writes,"committed":false})
}

fn unwritten_receipt(kind: &'static str) -> AssetWrite {
    AssetWrite {
        kind,
        written: Some(false),
        durability_confirmed: Some(false),
    }
}

fn unwritten(assets: &[GeoAssetSnapshot]) -> Vec<AssetWrite> {
    assets
        .iter()
        .map(|asset| AssetWrite {
            kind: asset.kind,
            written: Some(false),
            durability_confirmed: Some(false),
        })
        .collect()
}

impl Worker {
    pub(super) async fn perform_geodata(&mut self, plan: GeoUpdatePlan, reservation: Reservation) {
        let id = &reservation.id;
        self.service.operations.accept(id);
        self.service.operations.running(id);
        let mut activated = false;
        match self.update_geodata(&plan, &mut activated).await {
            Ok(data) => {
                self.service
                    .operations
                    .succeed(id, OperationResult::Geodata(data));
                if activated {
                    self.reloaded(id);
                }
            }
            Err(details) => {
                let checksum = plan.sources.is_some()
                    && details["stage"]
                        .as_str()
                        .is_some_and(|stage| stage.starts_with("checksum_"));
                if checksum {
                    tracing::warn!(
                        %details,
                        "geodata update failed; for a mirror that publishes no usable .sha256sum, setting geodata.verify_checksum to false turns the check off"
                    );
                } else {
                    tracing::warn!(%details, "geodata update failed");
                }
                if let Some(sources) = &plan.sources {
                    sources.record(Err(details["stage"]
                        .as_str()
                        .unwrap_or("activation_failed")
                        .to_owned()));
                }
                if activated {
                    self.failed(
                        id,
                        "geodata_update_failed",
                        "Geodata update did not complete successfully",
                        Some(details),
                    );
                } else {
                    self.service.operations.fail(
                        id,
                        "geodata_update_failed",
                        "Geodata update did not complete successfully",
                        Some(details),
                    );
                }
            }
        }
    }

    /// Sets `activated` once the new assets reach activation, so the caller
    /// records `last_reload` only for updates that reloaded the runtime.
    async fn update_geodata(
        &mut self,
        plan: &GeoUpdatePlan,
        activated: &mut bool,
    ) -> Result<geodata::GeoData, Value> {
        let writes = unwritten(&plan.assets);
        let active = self.active.read().await.clone();
        let accepted = self
            .service
            .sources
            .accepted
            .read()
            .clone()
            .ok_or_else(|| failure("source_authority_lost", &writes))?;
        if accepted.revision != plan.revision
            || !self.service.writable()
            || geodata::capture_assets(&plan.traffic_router, &self.active, &plan.dns)
                .await
                .map_err(|_| failure("loaded_assets_unavailable", &writes))?
                .0
                != plan.assets
        {
            return Err(failure("revision_conflict", &writes));
        }
        let mut downloads = Vec::with_capacity(plan.assets.len());
        let mut fetched = Vec::with_capacity(plan.assets.len());
        let egress = geodata::Egress {
            bootstrap: &active.global.bootstrap_resolver,
            route: &plan.route,
            outbounds: Outbounds {
                router: &plan.traffic_router,
                config: &self.active,
                group_manager: &plan.group_manager,
                proxy_registry: &plan.proxy_registry,
                runtime_registry: &plan.runtime_registry,
            },
        };
        let mut stopping = self.stopping.clone();
        for (asset, urls) in plan.assets.iter().zip(&plan.urls) {
            // Shutdown must not wait out `DOWNLOAD_LIMIT`; nothing is written yet.
            let result = tokio::select! {
                biased;
                _ = stopping.wait_for(|stopped| *stopped) => {
                    return Err(failure("coordinator_stopped", &writes));
                }
                result = geodata::fetch(
                    asset.kind,
                    urls,
                    &egress,
                    offline::MAX_ASSET_BYTES,
                    plan.verify_checksum,
                ) => result,
            };
            let (bytes, origin) = result.map_err(|error| {
                let mut details = failure(error.code, &writes);
                details["asset"] = json!(asset.kind);
                if let Some(status) = error.status {
                    details["http_status"] = json!(status);
                }
                details
            })?;
            downloads.push(DownloadedAsset {
                original: asset.clone(),
                unchanged: digest(&bytes) == asset.sha256,
                bytes,
            });
            fetched.push(origin);
        }
        let service = Arc::clone(&self.service);
        let store = self.store.clone();
        let revision = plan.revision.clone();
        let data_dir = self.data_dir.clone();
        let deferred = self
            .subscriptions
            .deferred_subscriptions()
            .await
            .map_err(|_| failure("subscription_owner_unavailable", &writes))?;
        let prepared = tokio::task::spawn_blocking(move || {
            prepare_and_replace(
                &service, &store, &active, &accepted, downloads, &revision, &data_dir, &deferred,
            )
        })
        .await
        .map_err(|_| {
            failure(
                "write_completion_unconfirmed",
                writes.iter().map(|write| AssetWrite {
                    kind: write.kind,
                    written: None,
                    durability_confirmed: None,
                }),
            )
        })??;
        // Identical bytes leave the loaded files and the generation as they are.
        let Some(PreparedGeodata {
            activation,
            assets: prepared,
        }) = prepared
        else {
            if let Some(sources) = &plan.sources {
                sources.record(Ok((fetched, false)));
            }
            let (assets, published) =
                geodata::capture_assets(&plan.traffic_router, &self.active, &plan.dns)
                    .await
                    .map_err(|_| failure("loaded_assets_unavailable", &writes))?;
            return Ok(self.project(plan, assets, &published));
        };
        *activated = true;
        self.activation
            .activate(activation)
            .await
            .map_err(|failure| {
                let mut details = failure
                    .management_error(true, &self.service.instance_id)
                    .into_details()
                    .unwrap_or_else(|| json!({"committed":null}));
                details["assets"] = json!(
                    prepared
                        .iter()
                        .map(|asset| &asset.receipt)
                        .collect::<Vec<_>>()
                );
                details
            })?;
        let (assets, published) =
            geodata::capture_assets(&plan.traffic_router, &self.active, &plan.dns)
                .await
                .map_err(|_| {
                    let mut details = failure(
                        "published_assets_unavailable",
                        prepared.iter().map(|asset| &asset.receipt),
                    );
                    details["committed"] = json!(true);
                    details
                })?;
        // A kept file may still be published under the path its unchanged router recorded.
        if assets.len() != prepared.len()
            || assets.iter().zip(&prepared).any(|(actual, prepared)| {
                let expected = &prepared.snapshot;
                actual.kind != expected.kind
                    || (prepared.receipt.written == Some(true) && actual.path != expected.path)
                    || actual.sha256 != expected.sha256
                    || actual.size_bytes != expected.size_bytes
            })
        {
            let mut details = failure(
                "published_assets_mismatch",
                prepared.iter().map(|asset| &asset.receipt),
            );
            details["committed"] = json!(true);
            return Err(details);
        }
        if let Some(sources) = &plan.sources {
            let replaced = plan
                .assets
                .iter()
                .zip(&prepared)
                .any(|(original, prepared)| original.sha256 != prepared.snapshot.sha256);
            sources.record(Ok((fetched, replaced)));
        }
        Ok(self.project(plan, assets, &published))
    }

    fn project(
        &self,
        plan: &GeoUpdatePlan,
        assets: Vec<GeoAssetSnapshot>,
        published: &Config,
    ) -> geodata::GeoData {
        geodata::project(
            assets,
            plan.sources.as_deref(),
            published,
            &self.service,
            |name| geodata::group_id(&plan.catalog, name),
        )
    }
}

fn subscription_dependency(dependency: &DependencySnapshot) -> bool {
    dependency
        .readers
        .iter()
        .any(|reader| matches!(reader, DependencyReader::Subscription(_)))
}

/// Whether the dependencies the accepted configuration was admitted with still
/// describe the disk, apart from subscription caches: the subscription owner
/// rewrites those on every refresh without a new source acceptance, so a
/// refreshed body is not a conflict with the sources the update is based on.
/// The caches still fence the write itself, through the recapture that runs
/// under the staged replacement.
fn same_settled_dependencies(
    accepted: &[DependencySnapshot],
    captured: &[DependencySnapshot],
) -> bool {
    let settled = |dependency: &&DependencySnapshot| !subscription_dependency(dependency);
    accepted
        .iter()
        .filter(settled)
        .eq(captured.iter().filter(settled))
}

/// `None` when every download matches its loaded file: nothing is written,
/// but the loaded files still pass the checks a write would run first.
#[allow(clippy::too_many_arguments)]
fn prepare_and_replace(
    service: &ConfigService,
    store: &SourceStore,
    active: &Config,
    accepted: &Accepted,
    downloads: Vec<DownloadedAsset>,
    revision: &str,
    data_dir: &Path,
    deferred: &[honk_config::subscription::Subscription],
) -> Result<Option<PreparedGeodata>, Value> {
    let writes: Vec<_> = downloads
        .iter()
        .map(|asset| unwritten_receipt(asset.original.kind))
        .collect();
    let mut diagnostics = Vec::new();
    let loaded = store
        .load(&HashMap::new(), &mut diagnostics)
        .map_err(|_| failure("source_conflict", &writes))?;
    if !same_source_documents(&accepted.update.sources, &loaded.sources)
        || service.sources.revision().as_deref() != Some(revision)
    {
        return Err(failure("source_conflict", &writes));
    }
    let requirements = GeoRequirements::for_traffic(&loaded.config.routing.rules).union(
        &crate::dns::routing::DnsRouter::geo_requirements(&loaded.config.dns),
    );
    let mut captured = offline::capture_for_coordinator(
        loaded,
        store.dependency_root(),
        active,
        data_dir,
        SourceLimits::DEFAULT,
        &mut diagnostics,
        deferred,
        None,
    )
    .map_err(|_| failure("dependency_validation_failed", &writes))?;
    // Only the dependency snapshots are needed from the loaded assets.
    captured.release_geo();
    if !accepted.update.dependencies.is_empty()
        && !same_settled_dependencies(&accepted.update.dependencies, &captured.dependencies)
    {
        return Err(failure("dependency_conflict", &writes));
    }
    let mut source_pins = Vec::new();
    for source in &captured.sources {
        let pin = store
            .pin(&source.path)
            .map_err(|_| failure("source_conflict", &writes))?;
        if pin.sha256() != digest(source.content.as_bytes()) {
            return Err(failure("source_conflict", &writes));
        }
        source_pins.push(pin);
    }
    let mut guards = Vec::new();
    // Subscription labels name SQLite rows; the pre-rename recapture fences their bytes.
    for dependency in captured
        .dependencies
        .iter()
        .filter(|dependency| !dependency.asset && !subscription_dependency(dependency))
    {
        let file = SourceFile::open_binary(&dependency.path, MAX_SOURCE_BYTES)
            .map_err(|_| failure("dependency_conflict", &writes))?;
        if file.sha256() != dependency.sha256 {
            return Err(failure("dependency_conflict", &writes));
        }
        guards.push(file);
    }
    let mut assets: std::collections::VecDeque<StagedAsset> =
        std::collections::VecDeque::with_capacity(downloads.len());
    let mut kept: Vec<KeptAsset> = Vec::new();
    let resolved_data_dir = std::fs::canonicalize(data_dir);
    for download in downloads {
        let original = download.original;
        let recorded = original
            .path
            .as_ref()
            .ok_or_else(|| failure("asset_path_unavailable", &writes))?;
        // A reload keeps a router whose asset bytes did not change, so the path
        // it recorded can name a file the lookup no longer resolves. The loaded
        // asset is the resolved file with those bytes, which a reload or restart
        // would load again.
        let dependency = captured
            .dependencies
            .iter()
            .find(|dependency| {
                dependency.asset
                    && dependency.sha256 == original.sha256
                    && dependency
                        .readers
                        .contains(&DependencyReader::Geo(original.kind))
            })
            .ok_or_else(|| failure("asset_conflict", &writes))?;
        let path = if std::fs::canonicalize(recorded).is_ok_and(|path| path == dependency.path) {
            recorded.clone()
        } else {
            dependency.path.clone()
        };
        // `path` may pass through symlinks, as packaged assets and a data
        // directory under `/var -> tmp` do on OpenWrt. The canonical path names
        // the same file and is the one the capture read.
        let file = SourceFile::open_binary(&dependency.path, offline::MAX_ASSET_BYTES)
            .map_err(|_| failure("asset_path_unavailable", &writes))?;
        if file.sha256() != original.sha256 {
            return Err(failure("asset_conflict", &writes));
        }
        if guards
            .iter()
            .chain(source_pins.iter().filter_map(|pin| match pin {
                Pin::File(file) => Some(file),
                Pin::Revision(..) => None,
            }))
            .chain(kept.iter().map(|asset| &asset.file))
            .any(|other| file.same_target(other))
            || assets.iter().any(|asset| asset.staged.same_target(&file))
        {
            return Err(failure("asset_alias", &writes));
        }
        if download.unchanged {
            kept.push(KeptAsset {
                snapshot: GeoAssetSnapshot {
                    modified_at: original.modified_at.filter(|_| path == *recorded),
                    path: Some(path),
                    ..original
                },
                bytes: download.bytes,
                file,
            });
            continue;
        }
        let name = recorded.file_name().unwrap_or_default();
        let (staged, target) = match update_target(
            &dependency.path,
            name,
            data_dir,
            std::env::var_os("DAE_LOCATION_ASSET")
                .as_deref()
                .map(Path::new),
        ) {
            None => (file.stage(&original.sha256, &download.bytes), path),
            // The operator configures the data directory, so its symlinks are
            // resolved; staging still refuses any symlink below it.
            Some(target) => (
                resolved_data_dir
                    .as_ref()
                    .map_or(Err(WriteError::Unavailable), |directory| {
                        file.stage_beside(&original.sha256, &directory.join(name), &download.bytes)
                    }),
                target,
            ),
        };
        let staged = staged.map_err(|_| failure("staging_failed", &writes))?;
        let snapshot = GeoAssetSnapshot {
            kind: original.kind,
            path: Some(target),
            sha256: staged.sha256().to_owned(),
            size_bytes: download.bytes.len() as u64,
            modified_at: staged.modified_at(),
        };
        assets.push_back(StagedAsset {
            snapshot,
            bytes: download.bytes,
            staged,
        });
    }
    if assets.is_empty() {
        return Ok(None);
    }
    let geo = GeoSourceSet::from_assets(
        &requirements,
        assets
            .iter()
            .map(|asset| (asset.snapshot.clone(), Arc::clone(&asset.bytes)))
            .chain(
                kept.iter()
                    .map(|asset| (asset.snapshot.clone(), Arc::clone(&asset.bytes))),
            )
            .collect(),
    )
    .map_err(|_| failure("asset_validation_failed", &writes))?;
    let validated = captured
        .with_geo(geo)
        .and_then(offline::CapturedConfig::validate)
        .map_err(|_| failure("candidate_validation_failed", &writes))?;
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        return Err(failure("candidate_validation_failed", &writes));
    }
    let mut installed: Vec<InstalledAsset> = Vec::with_capacity(assets.len());
    while let Some(StagedAsset {
        snapshot, staged, ..
    }) = assets.pop_front()
    {
        let mut receipt = AssetWrite {
            kind: snapshot.kind,
            written: Some(false),
            durability_confirmed: Some(false),
        };
        let report = |stage, receipt| {
            failure(
                stage,
                installed
                    .iter()
                    .map(|asset| asset.receipt)
                    .chain(std::iter::once(receipt))
                    .chain(
                        assets
                            .iter()
                            .map(|asset| unwritten_receipt(asset.snapshot.kind)),
                    )
                    .chain(
                        kept.iter()
                            .map(|asset| unwritten_receipt(asset.snapshot.kind)),
                    ),
            )
        };
        let result = staged.replace(|| {
            #[cfg(test)]
            {
                let hook = service.before_replace.lock().take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            if service.sources.revision().as_deref() != Some(revision) {
                return Err(WriteError::Conflict);
            }
            for pin in &source_pins {
                pin.recheck()?;
            }
            for guard in guards.iter().chain(kept.iter().map(|asset| &asset.file)) {
                guard.recheck()?;
            }
            for completed in &installed {
                completed.installed.recheck()?;
            }
            for pending in &assets {
                pending.staged.recheck()?;
            }
            unchanged(
                store,
                &HashMap::new(),
                &validated,
                active,
                data_dir,
                deferred,
            )
        });
        let completed = match result {
            Ok(completed) => completed,
            Err(WriteError::ChangedButNotDurable) => {
                receipt.written = Some(true);
                return Err(report("directory_sync_failed", receipt));
            }
            Err(_) => return Err(report("replacement_failed", receipt)),
        };
        receipt.written = Some(true);
        receipt.durability_confirmed = Some(completed.durability_confirmed);
        if !completed.durability_confirmed {
            return Err(report("directory_sync_failed", receipt));
        }
        completed
            .file
            .recheck()
            .map_err(|_| report("written_asset_conflict", receipt))?;
        installed.push(InstalledAsset {
            snapshot,
            installed: completed.file,
            receipt,
        });
    }
    installed.extend(kept.into_iter().map(|asset| InstalledAsset {
        receipt: unwritten_receipt(asset.snapshot.kind),
        snapshot: asset.snapshot,
        installed: asset.file,
    }));
    installed.sort_by_key(|asset| asset.snapshot.kind != "geosite");
    for pin in &source_pins {
        pin.recheck().map_err(|_| {
            failure(
                "postwrite_conflict",
                installed.iter().map(|asset| &asset.receipt),
            )
        })?;
    }
    for guard in guards
        .iter()
        .chain(installed.iter().map(|asset| &asset.installed))
    {
        guard.recheck().map_err(|_| {
            failure(
                "postwrite_conflict",
                installed.iter().map(|asset| &asset.receipt),
            )
        })?;
    }
    Ok(Some(PreparedGeodata {
        activation: ActivationRequest {
            candidate: validated.config,
            sources: Some(SourceUpdate {
                sources: validated.sources,
                dependencies: validated.dependencies,
                geo_sources: validated.geo_sources,
            }),
            diagnostics,
            expected_group_revision: Some(revision.to_owned()),
            deferred_provider: None,
        },
        assets: installed,
    }))
}

/// Where an update writes the replacement for the loaded file at `resolved`,
/// a canonical path: `None` replaces it in place, which happens only when that
/// file is in the data directory or in the explicit asset directory that
/// outranks it. Otherwise the new file goes into the data directory under the
/// lookup's `name` and shadows the old one in the lookup order, so a file a
/// package manager installed is never overwritten. Because `resolved` has no
/// symlinks, a link from a packaged directory is judged by the file it names,
/// and an update never writes through it.
fn update_target(
    resolved: &Path,
    name: &std::ffi::OsStr,
    data_dir: &Path,
    explicit: Option<&Path>,
) -> Option<PathBuf> {
    let same = |directory: &Path| {
        resolved.parent().is_some_and(|parent| {
            parent == directory
                || std::fs::canonicalize(directory).is_ok_and(|directory| parent == directory)
        })
    };
    if same(data_dir) || explicit.is_some_and(same) {
        return None;
    }
    Some(data_dir.join(name))
}

#[cfg(test)]
mod settled_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn updates_write_to_the_data_directory_instead_of_a_packaged_file() {
        let data = Path::new("/var/lib/honk");
        let explicit = Some(Path::new("/opt/assets"));
        let name = std::ffi::OsStr::new("geosite.dat");
        for packaged in ["/usr/share/honk/geosite.dat", "/usr/share/dae/geosite.dat"] {
            assert_eq!(
                update_target(Path::new(packaged), name, data, None),
                Some(data.join("geosite.dat"))
            );
            assert_eq!(
                update_target(Path::new(packaged), name, data, explicit),
                Some(data.join("geosite.dat"))
            );
        }
        assert_eq!(
            update_target(&data.join("geosite.dat"), name, data, None),
            None
        );
        assert_eq!(
            update_target(Path::new("/opt/assets/geosite.dat"), name, data, explicit),
            None
        );
    }

    /// OpenWrt links `/usr/share/dae/geo*.dat` to `../v2ray/geo*.dat` and
    /// links `/var` to `tmp`, the data directory's parent.
    #[test]
    fn updates_read_through_symlinks_and_write_only_into_the_data_directory() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let vendor = root.join("usr/share/v2ray");
        let packaged = root.join("usr/share/dae");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&packaged).unwrap();
        std::fs::create_dir_all(root.join("tmp/lib/honk")).unwrap();
        std::os::unix::fs::symlink("tmp", root.join("var")).unwrap();
        std::fs::write(vendor.join("geoip.dat"), b"old").unwrap();
        std::os::unix::fs::symlink("../v2ray/geoip.dat", packaged.join("geoip.dat")).unwrap();
        let data_dir = root.join("var/lib/honk");
        let recorded = packaged.join("geoip.dat");
        let resolved = std::fs::canonicalize(&recorded).unwrap();
        assert_eq!(resolved, vendor.join("geoip.dat"));

        let name = recorded.file_name().unwrap();
        let target = update_target(&resolved, name, &data_dir, None);
        assert_eq!(target, Some(data_dir.join("geoip.dat")));
        let file = SourceFile::open_binary(&resolved, 1024).unwrap();
        let directory = std::fs::canonicalize(&data_dir).unwrap();
        let hash = file.sha256();
        let installed = file
            .stage_beside(&hash, &directory.join(name), b"new")
            .unwrap()
            .replace(|| Ok(()))
            .unwrap();
        assert!(installed.durability_confirmed);
        assert_eq!(std::fs::read(data_dir.join("geoip.dat")).unwrap(), b"new");
        assert_eq!(std::fs::read(vendor.join("geoip.dat")).unwrap(), b"old");
        assert!(
            std::fs::symlink_metadata(&recorded)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // The next update finds the new file through the linked prefix and
        // replaces it in place.
        let recorded = data_dir.join("geoip.dat");
        let resolved = std::fs::canonicalize(&recorded).unwrap();
        assert_eq!(resolved, root.join("tmp/lib/honk/geoip.dat"));
        assert_eq!(update_target(&resolved, name, &data_dir, None), None);
        let file = SourceFile::open_binary(&resolved, 1024).unwrap();
        let hash = file.sha256();
        file.stage(&hash, b"newer")
            .unwrap()
            .replace(|| Ok(()))
            .unwrap();
        assert_eq!(std::fs::read(&recorded).unwrap(), b"newer");
        assert_eq!(std::fs::read(vendor.join("geoip.dat")).unwrap(), b"old");
    }

    /// A link inside the data directory to a packaged file is judged by its
    /// target: the update never writes through it and never replaces the link.
    #[test]
    fn a_link_in_the_data_directory_is_neither_written_through_nor_replaced() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let data_dir = root.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(root.join("geoip.dat"), b"old").unwrap();
        std::os::unix::fs::symlink(root.join("geoip.dat"), data_dir.join("geoip.dat")).unwrap();
        let resolved = std::fs::canonicalize(data_dir.join("geoip.dat")).unwrap();
        let name = std::ffi::OsStr::new("geoip.dat");
        let target = update_target(&resolved, name, &data_dir, None).unwrap();
        let file = SourceFile::open_binary(&resolved, 1024).unwrap();
        let hash = file.sha256();
        assert!(
            file.stage_beside(&hash, &target, b"new")
                .unwrap()
                .replace(|| Ok(()))
                .is_err()
        );
        assert_eq!(std::fs::read(root.join("geoip.dat")).unwrap(), b"old");
        assert!(
            std::fs::symlink_metadata(data_dir.join("geoip.dat"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    fn dependency(path: &str, sha256: &str, readers: Vec<DependencyReader>) -> DependencySnapshot {
        DependencySnapshot {
            path: PathBuf::from(path),
            sha256: sha256.to_owned(),
            bytes: 1,
            asset: readers
                .iter()
                .any(|reader| matches!(reader, DependencyReader::Geo(_))),
            readers,
        }
    }

    #[test]
    fn a_refreshed_subscription_cache_is_not_a_conflict_but_a_changed_asset_is() {
        let accepted = vec![
            dependency(
                "/state/geosite.dat",
                "aa",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/state/.sub/one",
                "11",
                vec![DependencyReader::Subscription(0)],
            ),
        ];
        let refreshed = vec![
            dependency(
                "/state/geosite.dat",
                "aa",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/state/.sub/one",
                "22",
                vec![DependencyReader::Subscription(0)],
            ),
        ];
        assert!(same_settled_dependencies(&accepted, &refreshed));
        let edited = vec![
            dependency(
                "/state/geosite.dat",
                "bb",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/state/.sub/one",
                "11",
                vec![DependencyReader::Subscription(0)],
            ),
        ];
        assert!(!same_settled_dependencies(&accepted, &edited));
        let hosts_changed = vec![
            dependency(
                "/state/geosite.dat",
                "aa",
                vec![DependencyReader::Geo("geosite")],
            ),
            dependency(
                "/etc/hosts",
                "cc",
                vec![DependencyReader::Hosts(0, "/etc/hosts".into())],
            ),
        ];
        assert!(!same_settled_dependencies(&accepted, &hosts_changed));
    }
}
