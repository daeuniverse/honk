//! `--store db` startup: run the active revision, or import `-c` as revision 1.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, anyhow, ensure};
use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::error::DetailedConfigError;
use honk_config::parser::source_edit::strip_listener_secrets;
use honk_config::parser::{LoadedConfig, SourceLimits, SourceSnapshot};

use super::super::config::ListenerSecrets;
use super::db::{DbStore, StoreError, StoredSecrets};
use crate::configuration::SourceUpdate;
use crate::state::StateDb;

pub(crate) struct DatabaseStartup {
    pub(crate) store: Arc<DbStore>,
    pub(crate) config: Config,
    pub(crate) sources: SourceUpdate,
    import: Option<Import>,
    /// The revision `config` was loaded from.
    head: Option<i64>,
}

struct Import {
    stripped: Vec<SourceSnapshot>,
    forbidden: ListenerSecrets,
    secrets: StoredSecrets,
}

pub(crate) enum ImportError {
    /// A listener secret value survives stripping in this file, for example in a comment or
    /// a file name; the db would keep it.
    SecretCopy(PathBuf),
    Load(DetailedConfigError),
    /// The stripped tree is not the same configuration over the same files.
    Changed,
}

/// `originals` of `original` read back from `entry` with every listener `secret:` removed,
/// and every secret value it held.
pub(crate) fn import_tree(
    entry: &Path,
    original: &Config,
    originals: &[SourceSnapshot],
) -> Result<(LoadedConfig, ListenerSecrets), ImportError> {
    let forbidden = ListenerSecrets::new(originals, "");
    let mut overlay = HashMap::new();
    for source in originals {
        let stripped = strip_listener_secrets(&source.content)
            .ok()
            .filter(|stripped| {
                !forbidden.contains(stripped) && !forbidden.contains(&source.path.to_string_lossy())
            })
            .ok_or_else(|| ImportError::SecretCopy(source.path.clone()))?;
        overlay.insert(source.path.clone(), Arc::<str>::from(stripped));
    }
    let mut loaded =
        Config::from_dae_sources_in_memory(entry, &overlay, SourceLimits::DEFAULT, &mut Vec::new())
            .map_err(ImportError::Load)?;
    if !(stripped_config_matches(original, &mut loaded.config)
        && loaded.sources.len() == originals.len()
        && loaded
            .sources
            .iter()
            .zip(originals)
            .all(|(stripped, original)| stripped.path == original.path))
    {
        return Err(ImportError::Changed);
    }
    Ok((loaded, forbidden))
}

/// Fresh parses generate identities and timestamps that are not declared source values.
pub(crate) fn stripped_config_matches(original: &Config, stripped: &mut Config) -> bool {
    stripped
        .experimental
        .native_api
        .secret
        .clone_from(&original.experimental.native_api.secret);
    stripped
        .experimental
        .clash_api
        .secret
        .clone_from(&original.experimental.clash_api.secret);
    for (node, original) in stripped.nodes.iter_mut().zip(&original.nodes) {
        node.created_at = original.created_at;
        node.updated_at = original.updated_at;
    }
    for (group, original) in stripped.groups.iter_mut().zip(&original.groups) {
        group.id = original.id;
        group.created_at = original.created_at;
    }
    for (subscription, original) in stripped
        .subscriptions
        .iter_mut()
        .zip(&original.subscriptions)
    {
        subscription.id = original.id;
        subscription.created_at = original.created_at;
    }
    stripped == original
}

impl DatabaseStartup {
    /// `entry` must be absolute and lexically normal; it is read only while the db is empty.
    pub(crate) fn open(
        entry: &Path,
        data_dir: &Path,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> anyhow::Result<Self> {
        let state = StateDb::open(data_dir).map_err(|error| store_error(error.into()))?;
        let store = Arc::new(DbStore::open(Arc::new(state), entry).map_err(store_error)?);
        if let Some((head, _)) = store.cached_head() {
            let loaded = store.load(&HashMap::new(), diagnostics)?;
            let config = crate::admit_operator_config(
                loaded.config,
                loaded.sources[0].source.clone(),
                diagnostics,
            )?;
            same_data_dir(&config, data_dir)?;
            no_clash_api(&config)?;
            return Ok(Self {
                store,
                config,
                sources: update(loaded.sources),
                import: None,
                head: Some(head),
            });
        }
        let (config, sources) = crate::load_operator_config_captured(store.entry(), diagnostics)
            .with_context(|| {
                format!(
                    "the configuration db is empty and {} cannot be imported",
                    entry.display()
                )
            })?;
        let originals = sources
            .ok_or_else(|| anyhow!("--store db imports a dae source tree"))?
            .sources;
        let native = &config.experimental.native_api;
        ensure!(
            native.enabled && native.config_write && native.credentialed(),
            "--store db needs experimental.native_api with enabled, config_write and a credential"
        );
        no_clash_api(&config)?;
        same_data_dir(&config, data_dir)?;
        let (loaded, forbidden) =
            import_tree(store.entry(), &config, &originals).map_err(|error| match error {
                ImportError::SecretCopy(path) => anyhow!(
                    "listener secrets in {} cannot be stripped completely; remove copies of secret values",
                    path.display()
                ),
                ImportError::Load(error) => error.into(),
                ImportError::Changed => anyhow!(
                    "{} does not read back the same once listener secrets are stripped",
                    entry.display()
                ),
            })?;
        let secrets = StoredSecrets {
            native_api: config.experimental.native_api.secret.clone(),
            clash_api: config.experimental.clash_api.secret.clone(),
        };
        Ok(Self {
            store,
            config,
            sources: update(loaded.sources.clone()),
            import: Some(Import {
                stripped: loaded.sources,
                forbidden,
                secrets,
            }),
            head: None,
        })
    }

    /// Call with the instance lock held: records the imported tree as revision 1,
    /// or refuses when another instance moved `head` after it was loaded.
    pub(crate) fn record(&mut self) -> anyhow::Result<()> {
        let Some(import) = self.import.take() else {
            let current = self.store.head().map_err(store_error)?;
            ensure!(
                current == self.head,
                "configuration db head moved from {:?} to {:?} during startup; start again",
                self.head,
                current
            );
            return Ok(());
        };
        self.store
            .initialize(
                &import.stripped,
                &import.forbidden,
                &import.secrets,
                "startup",
            )
            .map_err(store_error)?;
        Ok(())
    }
}

fn update(sources: Vec<SourceSnapshot>) -> SourceUpdate {
    SourceUpdate {
        sources,
        dependencies: Vec::new(),
        geo_sources: None,
    }
}

fn same_data_dir(config: &Config, data_dir: &Path) -> anyhow::Result<()> {
    ensure!(
        Path::new(&config.global.data_dir) == data_dir,
        "global.data_dir {} differs from --data-dir {}",
        config.global.data_dir,
        data_dir.display()
    );
    Ok(())
}

fn no_clash_api(config: &Config) -> anyhow::Result<()> {
    ensure!(
        config.experimental.clash_api.external_controller.is_empty(),
        "experimental.clash_api.external_controller is set; --store db runs without the Clash API"
    );
    Ok(())
}

fn store_error(error: StoreError) -> anyhow::Error {
    anyhow!("configuration db: {error}")
}

#[cfg(test)]
mod tests;
