//! `import` and revision activation: whole-tree candidates recorded as new revisions.

use super::*;
use crate::native_api::store::DbStore;
use crate::native_api::store::db::Origin;
use crate::native_api::store::startup::{ImportError, import_tree};

impl Worker {
    /// Reads the `-c` tree, strips its listener secrets and validates it as the next revision.
    pub(super) async fn prepare_import(&self, principal: &str) -> Result<Prepared, ApiError> {
        self.prepare_tree(principal, Some(Origin::Import), read_import)
            .await
    }

    /// Validates stored revision `number` as the next revision, recorded with `origin`;
    /// `None` re-activates `head` itself for a blocked store and records nothing.
    pub(super) async fn prepare_revision(
        &self,
        number: i64,
        principal: &str,
        origin: Option<Origin>,
    ) -> Result<Prepared, ApiError> {
        self.prepare_tree(principal, origin, move |database, diagnostics| {
            database
                .load_revision(number, diagnostics)
                .map_err(|_| unavailable().with_details(json!({"stage":"store"})))?
                .ok_or_else(not_found)
        })
        .await
    }

    async fn prepare_tree(
        &self,
        principal: &str,
        origin: Option<Origin>,
        read: impl FnOnce(&DbStore, &mut Vec<DetailedDiagnostic>) -> Result<LoadedConfig, ApiError>
        + Send
        + 'static,
    ) -> Result<Prepared, ApiError> {
        let SourceStore::Db(database) = self.store.clone() else {
            return Err(unsupported());
        };
        let check = self.candidate_check().await?;
        let principal = principal.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut diagnostics = Vec::new();
            let loaded = read(&database, &mut diagnostics)?;
            let validated = check.validate(loaded, &mut diagnostics, None, None, None)?;
            let committed = match origin {
                Some(origin) => Committed::Pending(
                    database
                        .stage(&validated.sources, &principal, origin)
                        .map_err(db_write_error)?,
                ),
                None => Committed::Resync,
            };
            Ok(prepared(validated, diagnostics, committed))
        })
        .await
        .map_err(|_| unavailable())?
    }
}

pub(super) fn read_import(
    database: &DbStore,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<LoadedConfig, ApiError> {
    let entry = database.import_entry();
    if entry != database.entry() {
        return Err(denied().with_reason(WriteRefusal::ImportEntryChanged));
    }
    let originals = Config::from_dae_file_with_sources(
        entry,
        &HashMap::new(),
        SourceLimits::DEFAULT,
        diagnostics,
    )
    .map_err(|error| config_error(error, diagnostics, &[], None, None))?;
    let (loaded, _) =
        import_tree(entry, &originals.config, &originals.sources).map_err(|error| match error {
            ImportError::SecretCopy(_) => management::unsupported_value(
                "A listener secret also appears outside its secret field",
                json!({"resource":"/x-honk/config/import","check":"secret_copy"}),
            )
            .with_reason(WriteRefusal::ListenerSecretInContent),
            ImportError::Load(error) => config_error(error, diagnostics, &[], None, None),
            ImportError::Changed => management::unsupported_value(
                "Removing listener secrets changes the configuration",
                json!({"resource":"/x-honk/config/import","check":"stripped_config"}),
            ),
        })?;
    Ok(loaded)
}
