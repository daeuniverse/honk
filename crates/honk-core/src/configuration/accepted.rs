use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use honk_config::parser::{SourceLimits, SourceSnapshot};
use parking_lot::{Mutex, RwLock};

use super::digest;

pub(crate) const MAX_SOURCE_BYTES: usize = SourceLimits::DEFAULT.max_bytes;
pub(crate) const MAX_SOURCES: usize = SourceLimits::DEFAULT.max_sources;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DependencyReader {
    Hosts(usize, String),
    Ech(usize, String),
    Subscription(usize),
    Geo(&'static str),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DependencySnapshot {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
    pub(crate) bytes: usize,
    /// Runtime assets remain fingerprinted but do not consume the operator source budget.
    pub(crate) asset: bool,
    pub(crate) readers: Vec<DependencyReader>,
}

impl std::fmt::Debug for DependencySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencySnapshot")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SourceUpdate {
    pub(crate) sources: Vec<SourceSnapshot>,
    pub(crate) dependencies: Vec<DependencySnapshot>,
    pub(crate) geo_sources: Option<crate::routing::GeoSourceSet>,
}

#[derive(Clone)]
pub(crate) struct Accepted {
    pub(crate) update: Arc<SourceUpdate>,
    pub(crate) ids: HashMap<PathBuf, String>,
    pub(crate) hashes: Vec<String>,
    pub(crate) revision: String,
    config_key: String,
    pub(crate) generation: u64,
    pub(crate) group_sources: HashMap<String, usize>,
    pub(crate) rule_sources: honk_config::parser::source_edit::RuleSourceIndex,
    pub(crate) accepted_at: SystemTime,
}

#[derive(Default)]
pub(crate) struct AcceptedSources {
    pub(crate) accepted: RwLock<Option<Accepted>>,
    entry: Mutex<Option<PathBuf>>,
}

pub(crate) struct PreparedAcceptance {
    expected: Option<(String, u64)>,
    accepted: Option<Accepted>,
}

impl AcceptedSources {
    pub(crate) fn invalidate(&self) {
        *self.accepted.write() = None;
    }

    pub(crate) fn generation_committed(&self, config_revision: &str, generation: u64) {
        if let Some(accepted) = self.accepted.write().as_mut() {
            if !accepted.config_key.is_empty() && accepted.config_key != config_revision {
                accepted.revision = uuid::Uuid::new_v4().to_string();
            }
            accepted.config_key = config_revision.to_owned();
            accepted.generation = generation;
        }
    }

    pub(crate) fn revision(&self) -> Option<String> {
        self.accepted
            .read()
            .as_ref()
            .map(|accepted| accepted.revision.clone())
    }

    pub(crate) fn available(&self) -> bool {
        self.accepted.read().is_some()
    }
    pub(crate) fn prepare_accept(&self, update: &SourceUpdate) -> PreparedAcceptance {
        let current = self.accepted.read().clone();
        let expected = current
            .as_ref()
            .map(|accepted| (accepted.revision.clone(), accepted.generation));
        let budgeted = update
            .dependencies
            .iter()
            .filter(|dependency| !dependency.asset);
        let valid = !update.sources.is_empty()
            && update.sources.len() + budgeted.clone().count() <= MAX_SOURCES
            && update
                .sources
                .iter()
                .map(|source| source.content.len())
                .chain(budgeted.map(|source| source.bytes))
                .try_fold(0usize, usize::checked_add)
                .is_some_and(|bytes| bytes <= MAX_SOURCE_BYTES)
            && self
                .entry
                .lock()
                .as_ref()
                .is_none_or(|path| path == &update.sources[0].path);
        if !valid {
            return PreparedAcceptance {
                expected,
                accepted: None,
            };
        }
        let Ok((group_sources, rule_sources)) =
            honk_config::parser::source_edit::source_indices(&update.sources)
        else {
            return PreparedAcceptance {
                expected,
                accepted: None,
            };
        };
        let hashes: Vec<_> = update
            .sources
            .iter()
            .map(|source| digest(source.content.as_bytes()))
            .collect();
        let same = current.as_ref().is_some_and(|current| {
            current.hashes == hashes
                && current
                    .update
                    .sources
                    .iter()
                    .map(|source| (&source.path, source.parent))
                    .eq(update
                        .sources
                        .iter()
                        .map(|source| (&source.path, source.parent)))
                && current.update.dependencies == update.dependencies
        });
        let ids = update
            .sources
            .iter()
            .map(|source| {
                let id = current
                    .as_ref()
                    .and_then(|current| current.ids.get(&source.path))
                    .cloned()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                (source.path.clone(), id)
            })
            .collect();
        let revision = if same {
            current.as_ref().unwrap().revision.clone()
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        let config_key = current
            .as_ref()
            .map(|current| current.config_key.clone())
            .unwrap_or_default();
        PreparedAcceptance {
            expected,
            accepted: Some(Accepted {
                update: Arc::new(SourceUpdate {
                    sources: update.sources.clone(),
                    dependencies: update.dependencies.clone(),
                    geo_sources: None,
                }),
                ids,
                hashes,
                revision,
                config_key,
                generation: 0,
                group_sources,
                rule_sources,
                accepted_at: SystemTime::now(),
            }),
        }
    }

    pub(crate) fn can_accept(&self, prepared: &PreparedAcceptance) -> bool {
        let current = self.accepted.read();
        same_identity(current.as_ref(), &prepared.expected)
    }

    /// Called only under the config publication barrier, after preparation and identity recheck.
    pub(crate) fn accept(&self, mut prepared: PreparedAcceptance, generation: u64) -> bool {
        let mut current = self.accepted.write();
        if !same_identity(current.as_ref(), &prepared.expected) {
            return false;
        }
        if let Some(accepted) = prepared.accepted.as_mut() {
            let mut entry = self.entry.lock();
            if entry
                .as_ref()
                .is_some_and(|path| path != &accepted.update.sources[0].path)
            {
                return false;
            }
            if entry.is_none() {
                *entry = Some(accepted.update.sources[0].path.clone());
            }
            accepted.generation = generation;
        }
        *current = prepared.accepted;
        true
    }
}

fn same_identity(current: Option<&Accepted>, expected: &Option<(String, u64)>) -> bool {
    match (current, expected) {
        (None, None) => true,
        (Some(current), Some((revision, generation))) => {
            current.revision == *revision && current.generation == *generation
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_sources_cannot_overwrite_a_newer_runtime_publication() {
        let service = AcceptedSources::default();
        let load = |content: &str| {
            let loaded = honk_config::parser::parse_dae_sources(
                &[(
                    PathBuf::from("/private/config.dae"),
                    Arc::<str>::from(content),
                )],
                SourceLimits::DEFAULT,
                &mut Vec::new(),
            )
            .unwrap();
            SourceUpdate {
                sources: loaded.sources,
                dependencies: Vec::new(),
                geo_sources: None,
            }
        };
        let original = load("routing { fallback: direct }\n");
        assert!(service.accept(service.prepare_accept(&original), 7));
        service.generation_committed("old-runtime", 7);
        let candidate = load("# new source bytes\nrouting { fallback: direct }\n");
        let prepared = service.prepare_accept(&candidate);
        service.generation_committed("new-runtime", 8);
        let current = service.accepted.read().clone().unwrap();
        assert!(!service.accept(prepared, 9));
        assert_eq!(
            service.revision().as_deref(),
            Some(current.revision.as_str())
        );
        assert_eq!(service.accepted.read().as_ref().unwrap().generation, 8);
        assert!(service.accept(service.prepare_accept(&candidate), 9));
        let guard = service.accepted.read();
        let accepted = guard.as_ref().unwrap();
        assert_eq!(accepted.ids, current.ids);
        assert_eq!(
            accepted.hashes[0],
            digest(candidate.sources[0].content.as_bytes())
        );
        assert_ne!(accepted.revision, current.revision);
    }
}
