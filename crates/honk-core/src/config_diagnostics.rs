use honk_config::diagnostic::{DetailedDiagnostic, DiagnosticSource, Severity, SourceRef};
use honk_config::subscription::Subscription;
use serde::Serialize;
use uuid::Uuid;

/// Diagnostics retained for the active configuration, grouped by provenance.
#[derive(Clone, Debug, Default)]
pub struct DiagnosticBuckets {
    pub static_diagnostics: Vec<DetailedDiagnostic>,
    pub providers: Vec<(Uuid, Vec<DetailedDiagnostic>)>,
}

pub(crate) enum DiagnosticUpdate {
    Preserve,
    Replace(DiagnosticBuckets),
    Rebase {
        static_diagnostics: Vec<DetailedDiagnostic>,
        retained_provider_ids: std::collections::HashSet<Uuid>,
    },
    ReplaceProvider {
        id: Uuid,
        diagnostics: Vec<DetailedDiagnostic>,
    },
}

impl DiagnosticBuckets {
    /// Replace one provider's retained body, preserving its bucket position.
    pub fn replace_provider(&mut self, id: Uuid, diagnostics: Vec<DetailedDiagnostic>) {
        if let Some((_, current)) = self
            .providers
            .iter_mut()
            .find(|(current, _)| *current == id)
        {
            *current = diagnostics;
        } else {
            self.providers.push((id, diagnostics));
        }
    }

    pub(crate) fn apply(&mut self, update: DiagnosticUpdate) {
        match update {
            DiagnosticUpdate::Preserve => {}
            DiagnosticUpdate::Replace(buckets) => *self = buckets,
            DiagnosticUpdate::Rebase {
                static_diagnostics,
                retained_provider_ids,
            } => {
                self.static_diagnostics = static_diagnostics;
                self.providers
                    .retain(|(id, _)| retained_provider_ids.contains(id));
            }
            DiagnosticUpdate::ReplaceProvider { id, diagnostics } => {
                self.replace_provider(id, diagnostics);
            }
        }
    }

    pub fn snapshot(&self, generation: u64, subscriptions: &[Subscription]) -> DiagnosticSnapshot {
        let mut projection = Projection::default();
        projection.push_bucket(&self.static_diagnostics);
        for subscription in subscriptions {
            if let Some((_, diagnostics)) =
                self.providers.iter().find(|(id, _)| *id == subscription.id)
            {
                projection.push_bucket(diagnostics);
            }
        }
        for (id, diagnostics) in &self.providers {
            if !subscriptions
                .iter()
                .any(|subscription| subscription.id == *id)
            {
                projection.push_bucket(diagnostics);
            }
        }
        projection.finish(generation)
    }
}

/// Active diagnostics and the datapath generation they describe.
#[derive(Clone, Debug, Default)]
pub struct ActiveDiagnostics {
    pub generation: u64,
    pub buckets: DiagnosticBuckets,
}

impl ActiveDiagnostics {
    pub fn snapshot(&self, subscriptions: &[Subscription]) -> DiagnosticSnapshot {
        self.buckets.snapshot(self.generation, subscriptions)
    }
}

pub type SharedDiagnostics = std::sync::Arc<parking_lot::RwLock<ActiveDiagnostics>>;

/// Public, metadata-only diagnostics for one active configuration generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticSnapshot {
    pub generation: u64,
    pub sources: Vec<DiagnosticSourceSnapshot>,
    pub diagnostics: Vec<DiagnosticSnapshotRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticSourceSnapshot {
    pub id: usize,
    /// Original zero-based local source-table ordinal; it is intentionally not compacted.
    pub ordinal: usize,
    pub parent: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticSnapshotRow {
    pub code: &'static str,
    pub severity: &'static str,
    pub source: usize,
    pub span: Option<std::ops::Range<usize>>,
    pub line: Option<usize>,
    pub byte_column: Option<usize>,
    pub setting: String,
    pub value: String,
    pub message: &'static str,
    pub entry_index: Option<usize>,
    pub related_indices: Vec<usize>,
    pub terminal: bool,
}

#[derive(Default)]
struct Projection<'a> {
    tables: Vec<Table>,
    rows: Vec<PendingRow<'a>>,
}

struct Table {
    source: honk_config::diagnostic::DiagnosticSources,
    metadata: Vec<DiagnosticSource>,
    referenced: Vec<bool>,
}

struct PendingRow<'a> {
    diagnostic: &'a DetailedDiagnostic,
    table: usize,
}

impl<'a> Projection<'a> {
    fn push_bucket(&mut self, diagnostics: &'a [DetailedDiagnostic]) {
        for diagnostic in diagnostics {
            let table = self.table_for(&diagnostic.source);
            self.include_ancestry(table, diagnostic.source.index());
            self.rows.push(PendingRow { diagnostic, table });
        }
    }

    fn table_for(&mut self, source: &SourceRef) -> usize {
        if let Some(index) = self
            .tables
            .iter()
            .position(|table| table.source.root().same_table(source))
        {
            return index;
        }
        let metadata = source.sources().metadata();
        let referenced = vec![false; metadata.len()];
        self.tables.push(Table {
            source: source.sources().clone(),
            metadata,
            referenced,
        });
        self.tables.len() - 1
    }

    fn include_ancestry(&mut self, table: usize, mut ordinal: usize) {
        while let Some(referenced) = self.tables[table].referenced.get_mut(ordinal) {
            if *referenced {
                break;
            }
            *referenced = true;
            let Some(parent) = self.tables[table]
                .metadata
                .get(ordinal)
                .and_then(|source| source.parent)
            else {
                break;
            };
            ordinal = parent;
        }
    }

    fn finish(self, generation: u64) -> DiagnosticSnapshot {
        let mut sources = Vec::new();
        let mut remapped = Vec::with_capacity(self.tables.len());
        for table in &self.tables {
            let mut ids = vec![None; table.metadata.len()];
            for (ordinal, referenced) in table.referenced.iter().copied().enumerate() {
                if referenced {
                    ids[ordinal] = Some(sources.len());
                    let parent = table.metadata[ordinal]
                        .parent
                        .and_then(|parent| ids[parent]);
                    sources.push(DiagnosticSourceSnapshot {
                        id: sources.len(),
                        ordinal,
                        parent,
                    });
                }
            }
            remapped.push(ids);
        }

        let diagnostics = self
            .rows
            .into_iter()
            .map(|row| {
                let source = remapped[row.table][row.diagnostic.source.index()]
                    .expect("diagnostic source must belong to its metadata table");
                DiagnosticSnapshotRow {
                    code: row.diagnostic.code,
                    severity: severity_name(row.diagnostic.severity),
                    source,
                    span: row.diagnostic.span.clone(),
                    line: row.diagnostic.line,
                    byte_column: row.diagnostic.byte_column,
                    setting: row.diagnostic.setting.to_string(),
                    value: row.diagnostic.value.to_string(),
                    message: row.diagnostic.message,
                    entry_index: row.diagnostic.entry_index,
                    related_indices: row.diagnostic.related_indices.clone(),
                    terminal: row.diagnostic.terminal,
                }
            })
            .collect();

        DiagnosticSnapshot {
            generation,
            sources,
            diagnostics,
        }
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::diagnostic::{DiagnosticSources, SafeValue, SettingPath};

    fn diagnostic(source: SourceRef, code: &'static str) -> DetailedDiagnostic {
        DetailedDiagnostic::warning(
            code,
            source,
            SettingPath::new("global").field("private_field"),
            SafeValue::Redacted,
            "safe diagnostic message",
        )
    }

    fn subscription(id: Uuid, name: &str) -> Subscription {
        Subscription {
            id,
            name: name.to_owned(),
            ..Subscription::default()
        }
    }

    #[test]
    fn remaps_tables_and_ancestors_deterministically() {
        let static_sources = DiagnosticSources::new(Some("private-static-path".into()));
        let include = static_sources.add(Some("private-include-path".into()), Some(0));
        let decoded = static_sources.add(None, Some(include.index()));
        let other_sources = DiagnosticSources::new(Some("private-other-path".into()));
        let first_provider_sources =
            DiagnosticSources::new(Some("private-first-provider-path".into()));
        let second_provider_sources =
            DiagnosticSources::new(Some("private-second-provider-path".into()));
        let first_provider = Uuid::from_u128(1);
        let second_provider = Uuid::from_u128(2);
        let configured = [
            subscription(second_provider, "private-second-provider-name"),
            subscription(first_provider, "private-first-provider-name"),
        ];

        let mut buckets = DiagnosticBuckets {
            static_diagnostics: vec![
                diagnostic(decoded, "child"),
                diagnostic(static_sources.root(), "root"),
                diagnostic(other_sources.root(), "other"),
            ],
            providers: vec![
                (
                    first_provider,
                    vec![diagnostic(first_provider_sources.root(), "first")],
                ),
                (
                    second_provider,
                    vec![diagnostic(second_provider_sources.root(), "second")],
                ),
            ],
        };
        // Provider storage order does not determine configured declaration order.
        buckets.providers.reverse();
        let snapshot = buckets.snapshot(7, &configured);

        assert_eq!(
            snapshot
                .sources
                .iter()
                .map(|source| source.ordinal)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 0, 0, 0],
        );
        assert_eq!(snapshot.sources[0].parent, None);
        assert_eq!(snapshot.sources[1].parent, Some(0));
        assert_eq!(snapshot.sources[2].parent, Some(1));
        assert_eq!(
            snapshot
                .diagnostics
                .iter()
                .map(|diagnostic| (diagnostic.code, diagnostic.source))
                .collect::<Vec<_>>(),
            vec![
                ("child", 2),
                ("root", 0),
                ("other", 3),
                ("second", 4),
                ("first", 5),
            ],
        );
    }
    #[test]
    fn omits_unreferenced_sources_but_keeps_referenced_ancestors() {
        let sources = DiagnosticSources::new(Some("root".into()));
        let _unused = sources.add(Some("unused".into()), Some(0));
        let child = sources.add(Some("child".into()), Some(0));
        let grandchild = sources.add(Some("grandchild".into()), Some(child.index()));
        let snapshot = DiagnosticBuckets {
            static_diagnostics: vec![diagnostic(grandchild, "used")],
            ..DiagnosticBuckets::default()
        }
        .snapshot(1, &[]);

        assert_eq!(
            snapshot
                .sources
                .iter()
                .map(|source| source.ordinal)
                .collect::<Vec<_>>(),
            vec![0, 2, 3],
        );
        assert_eq!(snapshot.diagnostics.len(), 1);
        assert_eq!(snapshot.diagnostics[0].source, 2);
        let empty = DiagnosticBuckets::default().snapshot(1, &[]);
        assert!(empty.sources.is_empty());
        assert!(empty.diagnostics.is_empty());
    }

    #[test]
    fn serialized_snapshot_contains_only_safe_projection_fields() {
        let sources = DiagnosticSources::new(Some("private-sentinel-path".into()));
        let id = Uuid::from_u128(30);
        let snapshot = DiagnosticBuckets {
            static_diagnostics: vec![diagnostic(sources.root(), "safe-code")],
            providers: vec![(id, vec![])],
        }
        .snapshot(4, &[subscription(id, "private-provider-name")]);
        let json = serde_json::to_string(&snapshot).unwrap();

        assert!(json.contains("safe-code"));
        assert!(json.contains("global.private_field"));
        assert!(!json.contains("private-sentinel-path"));
        assert!(!json.contains("private-provider-name"));
    }
}
