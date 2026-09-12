use std::collections::{BTreeMap, HashMap};

use super::read::Text;
use crate::diagnostic::{
    ConfigDiagnostic, DetailedDiagnostic, SafeValue, SettingPath, SourceRef, project_legacy,
};
use crate::error::DetailedConfigError;

#[derive(Clone)]
struct Location {
    source: SourceRef,
    line: Option<usize>,
    span: Option<std::ops::Range<usize>>,
    byte_column: Option<usize>,
}

#[derive(Clone)]
struct GroupLocation {
    location: Location,
    filters: Vec<Location>,
}

/// Attempt-local source coordinates; paths are constructed only when emitting diagnostics.
pub(super) struct ParserDiagnostics<'a> {
    pub output: &'a mut Vec<DetailedDiagnostic>,
    current: Location,
    fields: HashMap<String, Location>,
    groups: Vec<GroupLocation>,
    group: Option<usize>,
    subscription: Option<usize>,
    entry: Option<usize>,
    notices: Vec<(usize, DetailedDiagnostic)>,
    root: &'static str,
    attempt_start: usize,
}

impl<'a> ParserDiagnostics<'a> {
    pub fn new(output: &'a mut Vec<DetailedDiagnostic>, source: SourceRef) -> Self {
        Self {
            attempt_start: output.len(),
            root: "config",
            output,
            current: Location {
                source,
                line: None,
                span: None,
                byte_column: None,
            },
            fields: HashMap::new(),
            groups: Vec::new(),
            group: None,
            subscription: None,
            entry: None,
            notices: Vec::new(),
        }
    }

    pub fn source(&self) -> SourceRef {
        self.current.source.clone()
    }

    pub fn field_location(&self, field: &str) -> (SourceRef, Option<usize>) {
        let location = self.fields.get(field).unwrap_or(&self.current);
        (location.source.clone(), location.line)
    }

    pub fn parse_share_link(
        &mut self,
        link: &str,
    ) -> Result<crate::node::Node, crate::error::DetailedConfigError> {
        let source = self.source();
        let location = &self.current;
        let entry = self.entry;
        // Node tags are not schema fields: every link diagnostic belongs to this entry.
        let locate_entry = |diagnostic: &mut DetailedDiagnostic| {
            diagnostic.source = source.clone();
            diagnostic.line = location.line;
            diagnostic.span = location.span.clone();
            diagnostic.byte_column = location.byte_column;
            diagnostic.entry_index = entry;
            if let Some(crate::diagnostic::SettingSegment::Field(root)) =
                diagnostic.setting.0.first_mut()
                && *root == "config"
            {
                *root = "nodes";
            }
            if let Some(index) = entry {
                diagnostic
                    .setting
                    .0
                    .insert(1, crate::diagnostic::SettingSegment::Index(index));
            }
        };
        crate::node::Node::parse_share_link(link, &source, &mut |mut diagnostic| {
            locate_entry(&mut diagnostic);
            self.output.push(diagnostic);
        })
        .map_err(|mut error| {
            locate_entry(error.diagnostic.as_mut());
            error
        })
    }

    pub fn set_source(&mut self, source: SourceRef) {
        self.current = Location {
            source,
            line: None,
            span: None,
            byte_column: None,
        };
        self.fields.clear();
    }

    fn text_location(text: Text<'_, '_>) -> Location {
        let (line, column) = text.source.location(text.span.start);
        Location {
            source: text.source.reference(),
            line: Some(line),
            span: Some(text.span.start..text.span.end),
            byte_column: Some(column),
        }
    }

    pub fn at_text(&mut self, text: Text<'_, '_>) {
        self.current = Self::text_location(text);
    }

    pub fn register_field(&mut self, key: &str, text: Text<'_, '_>) {
        self.fields
            .insert(key.to_owned(), Self::text_location(text));
    }

    pub fn entry_text(&mut self, text: Text<'_, '_>, index: usize) {
        self.at_text(text);
        self.entry = Some(index);
    }

    pub fn begin_group_text(&mut self, text: Text<'_, '_>, index: usize) {
        self.at_text(text);
        self.fields.clear();
        self.entry = None;
        self.subscription = None;
        self.group = Some(index);
        self.groups.push(GroupLocation {
            location: self.current.clone(),
            filters: Vec::new(),
        });
    }

    pub fn remember_filter_text(&mut self, text: Text<'_, '_>) {
        self.groups
            .last_mut()
            .expect("group context")
            .filters
            .push(Self::text_location(text));
    }

    pub fn subscription_text(&mut self, text: Text<'_, '_>, index: usize) {
        self.at_text(text);
        self.fields.clear();
        self.entry = None;
        self.group = None;
        self.subscription = Some(index);
    }
    pub fn at_section(&mut self, name: &str, text: Text<'_, '_>) {
        self.at_text(text);
        self.root = match name {
            "node" => "nodes",
            "subscription" => "subscriptions",
            "group" => "groups",
            _ => "config",
        };
        self.group = None;
        self.subscription = None;
        self.entry = None;
        self.fields.clear();
    }

    pub fn select_group(&mut self, index: usize) {
        self.group = Some(index);
        self.subscription = None;
        self.entry = None;
        self.fields.clear();
        if let Some(group) = self.groups.get(index - 1) {
            self.current = group.location.clone();
        }
    }

    pub fn push(&mut self, legacy: ConfigDiagnostic) {
        let ttl = legacy.setting.starts_with("dns.fixed_domain_ttl.");
        let mut location = legacy
            .setting
            .rsplit('.')
            .next()
            .and_then(|key| self.fields.get(key))
            .cloned()
            .unwrap_or_else(|| self.current.clone());
        if ttl {
            location = self.current.clone();
        }
        let mut diagnostic = project_legacy(legacy, location.source.clone());
        if let Some(index) = self.group {
            if let Some(crate::diagnostic::SettingSegment::Field(field)) =
                diagnostic.setting.0.last().cloned()
            {
                diagnostic.setting = SettingPath::new("groups").index(index).field(field);
                if field == "filter"
                    && let SafeValue::Ordinal(ordinal) = diagnostic.value
                {
                    if let Some(filter) = self
                        .groups
                        .get(index - 1)
                        .and_then(|group| group.filters.get(ordinal - 1))
                    {
                        location = filter.clone();
                    }
                    diagnostic.entry_index = Some(ordinal);
                }
            }
        } else if let Some(index) = self.subscription {
            diagnostic.setting = SettingPath::new("subscriptions")
                .index(index)
                .field("interval");
            diagnostic.entry_index = Some(index);
        } else if ttl && let Some(index) = self.entry {
            diagnostic.setting = SettingPath::new("dns")
                .field("fixed_domain_ttl")
                .index(index);
            diagnostic.entry_index = Some(index);
        }
        diagnostic.source = location.source;
        if diagnostic.line.is_none() {
            diagnostic.line = location.line;
        }
        diagnostic.span = location.span;
        diagnostic.byte_column = location.byte_column;
        self.output.push(diagnostic);
    }

    pub fn notice(&mut self, mut diagnostic: DetailedDiagnostic) {
        diagnostic.setting = SettingPath::new(self.root);
        if let Some(group) = self.group {
            diagnostic.setting = SettingPath::new("groups").index(group).field("filter");
            if diagnostic.code == "empty-subgroup" {
                let ordinal = self.groups[group - 1].filters.len();
                diagnostic.setting = diagnostic.setting.index(ordinal);
                diagnostic.value = SafeValue::Ordinal(ordinal);
            }
        } else if let Some(entry) = self.entry {
            diagnostic.setting = diagnostic.setting.index(entry);
            diagnostic.entry_index = Some(entry);
        } else if let Some(subscription) = self.subscription {
            diagnostic.setting = diagnostic.setting.index(subscription);
        }
        self.notices.push((self.output.len(), diagnostic));
    }

    pub fn emit(&mut self, mut diagnostic: DetailedDiagnostic) {
        let field = diagnostic
            .setting
            .0
            .last()
            .and_then(|segment| match segment {
                crate::diagnostic::SettingSegment::Field(field) => Some(*field),
                _ => None,
            });
        let location = field
            .and_then(|field| self.fields.get(field))
            .unwrap_or(&self.current);
        if diagnostic.span.is_none() {
            diagnostic.source = location.source.clone();
            diagnostic.line = location.line;
            diagnostic.span = location.span.clone();
            diagnostic.byte_column = location.byte_column;
        }
        diagnostic.entry_index = self.entry;
        self.output.push(diagnostic);
    }

    pub fn remove(&mut self, index: usize) -> DetailedDiagnostic {
        self.flush(Some(index)).expect("existing diagnostic")
    }

    pub fn finish(&mut self) {
        self.flush(None);
    }

    fn flush(&mut self, remove: Option<usize>) -> Option<DetailedDiagnostic> {
        if self.notices.is_empty() {
            return remove.map(|index| self.output.remove(index));
        }
        let emitted = self.output.split_off(self.attempt_start);
        let capacity = emitted.len() + self.notices.len();
        let mut notices = std::mem::take(&mut self.notices).into_iter().peekable();
        let mut ordered = DiagnosticOrder {
            rows: Vec::with_capacity(capacity),
            ..DiagnosticOrder::default()
        };
        let mut target = None;
        for (index, diagnostic) in emitted.into_iter().enumerate() {
            while notices
                .peek()
                .is_some_and(|(before, _)| *before <= self.attempt_start + index)
            {
                ordered.insert(notices.next().unwrap().1, true);
            }
            if remove == Some(self.attempt_start + index) {
                target = Some(ordered.rows.len());
            }
            ordered.insert(diagnostic, false);
        }
        for (_, diagnostic) in notices {
            ordered.insert(diagnostic, true);
        }
        let mut next = ordered.head;
        let mut removed = None;
        while let Some(index) = next {
            let row = &mut ordered.rows[index];
            if Some(index) == target {
                removed = row.diagnostic.take();
            } else {
                self.output.push(row.diagnostic.take().unwrap());
            }
            next = row.next;
        }
        removed
    }

    pub fn error(&self, error: crate::ConfigError) -> DetailedConfigError {
        let mut error = DetailedConfigError::from_legacy(error, self.source());
        let field = error
            .diagnostic
            .setting
            .0
            .iter()
            .rev()
            .find_map(|segment| match segment {
                crate::diagnostic::SettingSegment::Field(field) => Some(*field),
                _ => None,
            });
        let location = field
            .and_then(|field| self.fields.get(field))
            .unwrap_or(&self.current);
        error.diagnostic.source = location.source.clone();
        error.diagnostic.line = location.line;
        error.diagnostic.span = location.span.clone();
        error.diagnostic.byte_column = location.byte_column;
        if error.diagnostic.code == "unknown-traffic-predicate"
            && let Some(index) = self.entry
        {
            error.diagnostic.setting = error.diagnostic.setting.clone().index(index);
            error.diagnostic.entry_index = Some(index);
        }
        error
    }
}

#[derive(Default)]
struct DiagnosticOrder {
    rows: Vec<OrderedDiagnostic>,
    head: Option<usize>,
    tail: Option<usize>,
    maxima: HashMap<SourceRef, BTreeMap<usize, usize>>,
}

struct OrderedDiagnostic {
    diagnostic: Option<DetailedDiagnostic>,
    previous: Option<usize>,
    next: Option<usize>,
}

impl DiagnosticOrder {
    fn insert(&mut self, diagnostic: DetailedDiagnostic, notice: bool) {
        let index = self.rows.len();
        let before = diagnostic.span.as_ref().and_then(|span| {
            let maxima = self.maxima.entry(diagnostic.source.clone()).or_default();
            // Only prefix maxima can be the first preceding row above this offset.
            let before = if notice {
                maxima
                    .range((
                        std::ops::Bound::Excluded(span.start),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(_, &row)| row)
            } else {
                None
            };
            if before.is_some()
                || maxima
                    .last_key_value()
                    .is_none_or(|(&last, _)| last < span.start)
            {
                maxima.entry(span.start).or_insert(index);
            }
            before
        });
        let previous = before.map_or(self.tail, |row| self.rows[row].previous);
        self.rows.push(OrderedDiagnostic {
            diagnostic: Some(diagnostic),
            previous,
            next: before,
        });
        if let Some(previous) = previous {
            self.rows[previous].next = Some(index);
        } else {
            self.head = Some(index);
        }
        if let Some(before) = before {
            self.rows[before].previous = Some(index);
        } else {
            self.tail = Some(index);
        }
    }
}
