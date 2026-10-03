//! Where the coordinator reads and writes the `.dae` sources it administers.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::error::DetailedConfigError;
use honk_config::parser::{LoadedConfig, SourceLimits, SourceSnapshot};

use super::ApiError;
use super::config_write::{SourceFile, WriteError};
use crate::configuration::MAX_SOURCE_BYTES;

pub(crate) mod db;
pub(crate) mod startup;

pub(crate) use db::DbStore;
pub(crate) use startup::DatabaseStartup;

/// Revision fence taken before a candidate is validated and checked again on commit.
#[allow(clippy::large_enum_variant)] // one per source for a single write
pub(crate) enum Pin {
    File(SourceFile),
    Revision(Arc<DbStore>, db::RevisionPin),
}

impl Pin {
    pub(crate) fn sha256(&self) -> String {
        match self {
            Self::File(file) => file.sha256(),
            Self::Revision(_, pin) => pin.sha256.clone(),
        }
    }

    pub(crate) fn recheck(&self) -> Result<(), WriteError> {
        match self {
            Self::File(file) => file.recheck(),
            Self::Revision(db, pin) => db.recheck(pin),
        }
    }

    /// `before` runs after the last precondition and must recheck the candidate.
    pub(crate) fn commit(
        self,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError> {
        match self {
            Self::File(file) => {
                file.replace(content, before)?;
                Ok(Committed::Written)
            }
            Self::Revision(db, pin) => db
                .commit(pin, content, candidate, principal, before)
                .map(Committed::Pending),
        }
    }
}

/// What `commit` left for `promote` once the candidate is active.
pub(crate) enum Committed {
    Written,
    Pending(db::Pending),
    /// `head` itself re-activated to bring a blocked store back in sync; records nothing.
    Resync,
}

impl Committed {
    pub(crate) fn written(&self) -> bool {
        matches!(self, Self::Written)
    }
}

/// Blocking source access; callers run it inside `spawn_blocking`.
#[derive(Clone)]
pub(crate) enum SourceStore {
    /// Sources read from and replaced in the operator's `-c` tree, named by its entry.
    File(Arc<Path>),
    Db(Arc<DbStore>),
}

impl SourceStore {
    pub(crate) fn entry(&self) -> &Path {
        match self {
            Self::File(entry) => entry,
            Self::Db(db) => db.entry(),
        }
    }

    /// Extra authorisation root for dependencies: the entry directory in file mode,
    /// `None` in db mode.
    pub(crate) fn dependency_root(&self) -> Option<&Path> {
        match self {
            Self::File(entry) => entry.parent(),
            Self::Db(_) => None,
        }
    }

    /// Map a client source label to the path the loader knows it by.
    pub(crate) fn resolve(&self, label: &str) -> Result<PathBuf, ApiError> {
        match self {
            Self::File(entry) => {
                let root = entry.parent().ok_or_else(super::config::invalid)?;
                super::config::resolve_source_path(root, label)
            }
            Self::Db(db) => db.resolve(label),
        }
    }

    pub(crate) fn load(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError> {
        match self {
            Self::File(entry) => Config::from_dae_file_with_sources(
                entry,
                overlay,
                SourceLimits::DEFAULT,
                diagnostics,
            ),
            Self::Db(db) => db.load(overlay, diagnostics),
        }
    }

    pub(crate) fn pin(&self, path: &Path) -> Result<Pin, WriteError> {
        match self {
            Self::File(_) => SourceFile::open(path, MAX_SOURCE_BYTES).map(Pin::File),
            Self::Db(db) => db.pin(path).map(|pin| Pin::Revision(Arc::clone(db), pin)),
        }
    }

    /// Adds `path` holding `content`, never replacing a source already there.
    /// `before` runs after the last precondition and must recheck the candidate.
    pub(crate) fn create(
        &self,
        path: &Path,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError> {
        match self {
            Self::File(entry) => {
                let mode = std::fs::metadata(entry)
                    .map_err(|_| WriteError::Unavailable)?
                    .mode();
                super::config_write::create_new(path, content.as_bytes(), mode, before)
                    .map(|()| Committed::Written)
            }
            Self::Db(db) => {
                // The entry's pin fences `head`; commit then checks the new path's content.
                let pin = db::RevisionPin {
                    path: path.to_owned(),
                    ..db.pin(db.entry())?
                };
                db.commit(pin, content, candidate, principal, before)
                    .map(Committed::Pending)
            }
        }
    }

    /// Records an activated candidate. A failure blocks later writes until restart.
    pub(crate) fn promote(&self, committed: Committed) -> Result<(), WriteError> {
        match (self, committed) {
            (Self::Db(db), Committed::Pending(pending)) => db.promote(pending).map(drop),
            (Self::Db(db), Committed::Resync) => {
                db.unblock();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Refuses later writes until restart: the running config may differ from the store.
    pub(crate) fn block(&self) {
        if let Self::Db(db) = self {
            db.block();
        }
    }

    /// True after a failed record: the daemon may run what the store does not hold.
    pub(crate) fn blocked(&self) -> bool {
        matches!(self, Self::Db(db) if db.blocked())
    }
}
