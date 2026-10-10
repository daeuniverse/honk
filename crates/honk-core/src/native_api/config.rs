//! Native file permissions, HTTP projections and configuration work admission.

mod coordinator;
mod http;
mod revisions;

pub(super) use http::{administrative_projection, create, get, reload, replace, source, validate};
pub(super) use revisions::{activate, export, import, revisions};

use axum::body::HttpBody;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use honk_config::{
    Config,
    diagnostic::{DetailedDiagnostic, Severity},
    experimental::NativeApiConfig,
    parser::{SourceLimits, SourceSnapshot, cursor::Document, lexer::Source},
};
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use super::operations::{OperationStore, Reservation};
use super::store::{SourceStore, db::MAX_REVISIONS};
use super::{
    ApiError, ErrorCode, NativeState, body, error, parse_query, timestamp,
    types::{RequestId, WriteRefusal},
};
use crate::configuration::{
    Accepted, AcceptedSources, MAX_SOURCE_BYTES, MAX_SOURCES, SourceUpdate,
};

/// Shorter secrets are not masked: a one-byte value would erase every
/// occurrence of that byte from every response.
pub(crate) const MIN_MASKED_SECRET: usize = 8;
/// Replacement and creation content bound: the body limit less the creation
/// envelope with a 1024-byte path, even if JSON escapes every path byte.
pub(super) const MAX_CONTENT_BYTES: usize = super::security::MAX_BODY_BYTES - 4096;

/// A rule's source id, redacted display file and masked location.
pub(crate) type LocatedRule = (
    String,
    String,
    honk_config::parser::source_edit::RuleSourceLocation,
);

/// The listener secret values a response must not carry. Building one parses every source that
/// holds an API secret, so `ConfigService` keeps the set for the accepted sources and rebuilds it
/// only when they change.
#[derive(Clone)]
pub(crate) struct ListenerSecrets {
    values: Vec<String>,
    /// Raw spellings borrow values; only distinct JSON escapes need another allocation.
    escaped: Vec<String>,
}

impl ListenerSecrets {
    pub(crate) fn new(sources: &[SourceSnapshot], native_secret: &str) -> Self {
        let mut values = Vec::new();
        if native_secret.len() >= MIN_MASKED_SECRET {
            values.push(native_secret.to_owned());
        }
        for source in sources.iter().filter(|source| source.contains_api_secret) {
            let Ok(document) = Document::parse(
                Source::new(&source.content, source.source.clone()),
                &mut Vec::new(),
            ) else {
                if !source.content.is_empty() {
                    values.push(source.content.to_string());
                }
                continue;
            };
            for field in document
                .sections()
                .filter(|root| root.header() == "experimental")
                .filter_map(|root| root.body())
                .flatten()
                .filter(|section| matches!(section.header().trim(), "native_api" | "clash_api"))
                .filter_map(|section| section.body())
                .flatten()
            {
                let span = field.header_span();
                let Some((key, value)) = source.content[span.start..span.end].split_once(':')
                else {
                    continue;
                };
                if key.trim() != "secret" {
                    continue;
                }
                let value = value.trim();
                let start = span.start + source.content[span.start..span.end].trim_end().len()
                    - value.len();
                let end = start + value.len();
                let quoted = document
                    .tokens()
                    .iter()
                    .flat_map(|token| &token.quoted)
                    .any(|quote| quote.start == start && quote.end == end);
                let value = if quoted {
                    &source.content[start + 1..end - 1]
                } else {
                    value
                };
                if value.len() >= MIN_MASKED_SECRET {
                    values.push(value.to_owned());
                }
            }
        }
        values.sort_unstable();
        values.dedup();
        values.into_iter().fold(Self::empty(), Self::push)
    }

    pub(crate) fn empty() -> Self {
        Self {
            values: Vec::new(),
            escaped: Vec::new(),
        }
    }

    pub(crate) fn from_config(config: &Config) -> Self {
        Self::empty().with_config(config)
    }

    /// Adds the effective secrets of `config`.
    pub(crate) fn with_config(self, config: &Config) -> Self {
        self.with_secret(&config.experimental.native_api.secret)
            .with_secret(&config.experimental.clash_api.secret)
    }

    /// Adds both effective secrets the configuration db holds.
    pub(crate) fn with_all(self, secrets: &super::store::db::StoredSecrets) -> Self {
        self.with_secret(&secrets.native_api)
            .with_secret(&secrets.clash_api)
    }

    pub(crate) fn with_secret(self, secret: &str) -> Self {
        if secret.len() >= MIN_MASKED_SECRET && !self.values.iter().any(|value| value == secret) {
            return self.push(secret.to_owned());
        }
        self
    }

    fn push(mut self, value: String) -> Self {
        let quoted = serde_json::to_string(&value).expect("listener secret is a string");
        let escaped = &quoted[1..quoted.len() - 1];
        if escaped != value {
            self.escaped.push(escaped.to_owned());
        }
        self.values.push(value);
        self
    }

    fn spellings(&self) -> impl Iterator<Item = &str> {
        self.values
            .iter()
            .chain(self.escaped.iter())
            .map(String::as_str)
    }

    pub(crate) fn contains(&self, text: &str) -> bool {
        self.spellings().any(|secret| text.contains(secret))
    }

    pub(crate) fn mask_borrowed<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        if self.contains(text) {
            std::borrow::Cow::Owned(self.mask(text).0)
        } else {
            std::borrow::Cow::Borrowed(text)
        }
    }

    pub(crate) fn mask(&self, text: &str) -> (String, bool) {
        if !self.contains(text) {
            return (text.to_owned(), false);
        }
        let mut hidden = vec![false; text.len()];
        for secret in self.spellings() {
            let mut offset = 0;
            while let Some(relative) = text[offset..].find(secret) {
                let start = offset + relative;
                hidden[start..start + secret.len()].fill(true);
                offset = start + text[start..].chars().next().unwrap().len_utf8();
            }
        }
        let mut masked = String::new();
        let mut hiding = false;
        for (index, character) in text.char_indices() {
            if hidden[index] {
                if !hiding {
                    masked.push_str("<redacted>");
                }
                if matches!(character, '\r' | '\n') {
                    masked.push(character);
                }
            } else {
                masked.push(character);
            }
            hiding = hidden[index];
        }
        (masked, true)
    }

    fn mask_display(&self, value: &mut Value) -> bool {
        let Some(text) = value.as_str() else {
            return false;
        };
        if !self.contains(text) {
            return false;
        }
        let (masked, changed) = self.mask(text);
        *value = json!(masked);
        changed
    }

    fn mask_value(&self, value: &mut Value) -> bool {
        let masked = match value {
            Value::Array(values) => values
                .iter_mut()
                .fold(false, |masked, value| self.mask_value(value) | masked),
            Value::Object(values) => values.iter_mut().fold(false, |masked, (key, value)| {
                let changed = if matches!(
                    key.as_str(),
                    "expression"
                        | "rule_expression"
                        | "domain"
                        | "pname"
                        | "src_mac"
                        | "outbound"
                        | "routed_outbound"
                        | "effective_outbound"
                        | "leaf_node_name"
                        | "member_name"
                        | "target"
                        | "name"
                        | "subscription_tag"
                        | "icon"
                        | "check_url"
                        | "final_outbound"
                        | "from_upstream"
                        | "upstream"
                        | "file"
                        | "path"
                        | "absolute_path"
                        | "url_redacted"
                        | "source_redacted"
                ) {
                    self.mask_display(value)
                } else if key == "chain"
                    && let Some(chain) = value.as_array_mut()
                {
                    chain
                        .iter_mut()
                        .fold(false, |masked, value| self.mask_display(value) | masked)
                } else {
                    self.mask_value(value)
                };
                changed | masked
            }),
            _ => false,
        };
        if masked && let Some(object) = value.as_object_mut() {
            if object.contains_key("trace_status") {
                object.insert("trace_status".into(), json!("partial"));
            }
            if let Some(trace) = object.get_mut("trace").and_then(Value::as_object_mut) {
                trace.insert("status".into(), json!("partial"));
                if let Some(missing) = trace.get_mut("missing").and_then(Value::as_array_mut)
                    && !missing.contains(&json!("redacted"))
                {
                    missing.push(json!("redacted"));
                }
            }
        }
        masked
    }
}

fn source_path(accepted: &Accepted, index: usize) -> &Path {
    let root = accepted.update.sources[0]
        .path
        .parent()
        .expect("accepted entry has a parent directory");
    accepted.update.sources[index]
        .path
        .strip_prefix(root)
        .expect("accepted sources are confined to the entry directory")
}

pub(crate) struct ConfigService {
    settings: NativeApiConfig,
    /// Restart-required like every listener secret, so the startup value masks every response.
    clash_secret: String,
    instance_id: String,
    operations: Arc<OperationStore>,
    pub(crate) sources: Arc<AcceptedSources>,
    sender: Mutex<Option<mpsc::Sender<Work>>>,
    last_reload: RwLock<Option<Value>>,
    phase: RwLock<Option<tokio::sync::watch::Receiver<crate::control::EnginePhase>>>,
    /// The secret set for the accepted sources, keyed by the `SourceUpdate` it was built from.
    secrets: Mutex<Option<(Arc<SourceUpdate>, Arc<ListenerSecrets>)>>,
    /// The accepted snapshot `warn_secret_collisions` last reported, by `SourceUpdate` and generation.
    warned: Mutex<Option<(Arc<SourceUpdate>, u64)>>,
    store: RwLock<Option<SourceStore>>,
    recording: RwLock<RecordState>,
    #[cfg(test)]
    before_replace: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

enum RecordState {
    Idle,
    /// The accepted revision before activation, if its source authority still existed.
    Pending(Option<String>),
}

enum Work {
    GeoUpdate {
        plan: Box<super::geodata::GeoUpdatePlan>,
        reservation: Reservation,
    },
    Manage {
        mutation: super::management::Mutation,
        catalog: Arc<crate::observe::catalog::Catalog>,
        group_manager: honk_outbound::group::SharedGroupManager,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        response: oneshot::Sender<Result<super::management::Completion, ApiError>>,
    },
    GroupPatch {
        patch: Box<super::groups::GroupPatch>,
        reservation: Reservation,
    },
    Replace {
        source_id: String,
        content: String,
        if_match: IfMatch,
        reservation: Reservation,
    },
    Create {
        path: String,
        content: String,
        reservation: Reservation,
    },
    Reload {
        reservation: Reservation,
    },
    Import {
        reservation: Reservation,
    },
    ActivateRevision {
        number: i64,
        reservation: Reservation,
    },
    Validate {
        request: ValidationRequest,
        response: oneshot::Sender<Result<Value, ApiError>>,
    },
    Sighup,
}

impl ConfigService {
    pub(crate) fn new(
        settings: NativeApiConfig,
        clash_secret: String,
        instance_id: String,
        operations: Arc<OperationStore>,
    ) -> Self {
        Self {
            settings,
            clash_secret,
            instance_id,
            operations,
            sources: Arc::new(AcceptedSources::default()),
            sender: Mutex::new(None),
            last_reload: RwLock::new(None),
            phase: RwLock::new(None),
            secrets: Mutex::new(None),
            warned: Mutex::new(None),
            store: RwLock::new(None),
            recording: RwLock::new(RecordState::Idle),
            #[cfg(test)]
            before_replace: Mutex::new(None),
        }
    }

    /// The principal recorded for writes that carry no reservation.
    pub(crate) fn principal(&self) -> &'static str {
        if self.settings.credentialed() {
            "control"
        } else {
            "anonymous"
        }
    }

    pub(crate) fn writable(&self) -> bool {
        self.write_refusal().is_none()
    }

    /// Why no configuration write is admitted now; `None` when writes are.
    pub(crate) fn write_refusal(&self) -> Option<WriteRefusal> {
        if !self.settings.config_write || !self.settings.credentialed() {
            Some(WriteRefusal::WritesDisabled)
        } else if !self.sources.available()
            || self
                .sender
                .lock()
                .as_ref()
                .is_none_or(mpsc::Sender::is_closed)
        {
            Some(WriteRefusal::ConfigurationUnavailable)
        } else {
            None
        }
    }

    /// True when the running configuration may differ from the recorded `head`.
    pub(crate) fn store_blocked(&self) -> bool {
        self.store.read().as_ref().is_some_and(SourceStore::blocked)
    }

    /// `store` of `GET /config`; reads only cached state.
    pub(crate) fn store_value(&self) -> Value {
        let Some(SourceStore::Db(store)) = self.store.read().clone() else {
            return json!({"kind":"file","revision":null,"parent":null,"recorded":true});
        };
        let recording = self.recording.read();
        let recorded = !store.blocked()
            && match &*recording {
                RecordState::Idle => true,
                RecordState::Pending(previous) => self
                    .sources
                    .accepted
                    .read()
                    .as_ref()
                    .is_some_and(|accepted| previous.as_ref() == Some(&accepted.revision)),
            };
        let head = store.cached_head();
        json!({"kind":"db","revision":head.map(|(number,_)|number),"parent":head.and_then(|(_,parent)|parent),"recorded":recorded})
    }

    /// `writable` as advertised: false while a failed record blocks writes.
    pub(crate) fn editable(&self) -> bool {
        self.writable() && !self.store_blocked()
    }

    pub(crate) fn import_capability(&self) -> Value {
        let database = matches!(*self.store.read(), Some(SourceStore::Db(_)));
        json!({"available":database && self.editable(),"replace_required":true})
    }

    pub(crate) fn revisions_capability(&self) -> Value {
        let database = matches!(*self.store.read(), Some(SourceStore::Db(_)));
        // Activating `head` stays possible while blocked: it is the way back in sync.
        json!({"available":database,"can_activate":database && self.writable(),"max_revisions":MAX_REVISIONS})
    }

    pub(crate) fn can_manage(&self) -> bool {
        self.manage_admission().is_ok()
    }

    /// The refusal `/nodes` and `/providers` writes get while the main source cannot take them.
    pub(super) fn manage_admission(&self) -> Result<(), ApiError> {
        let accepted = self.sources.accepted.read().clone();
        if let Some(reason) = self.write_refusal() {
            return Err(super::management::unsupported().with_reason(reason));
        }
        let accepted = accepted.ok_or_else(|| {
            super::management::unsupported().with_reason(WriteRefusal::ConfigurationUnavailable)
        })?;
        if let Some(reason) = self.source_refusal(&accepted, 0) {
            return Err(super::management::unsupported().with_reason(reason));
        }
        if self.store_blocked() {
            return Err(super::management::unsupported());
        }
        Ok(())
    }

    pub(super) async fn manage(
        &self,
        mutation: super::management::Mutation,
        catalog: Arc<crate::observe::catalog::Catalog>,
        group_manager: honk_outbound::group::SharedGroupManager,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    ) -> Result<super::management::Completion, ApiError> {
        let (response, wait) = oneshot::channel();
        self.enqueue(Work::Manage {
            mutation,
            catalog,
            group_manager,
            alive_set,
            response,
        })?;
        wait.await.map_err(|_| {
            super::management::activation_error("coordinator_stopped", None, None, None, None)
        })?
    }

    pub(super) fn queue_geodata(
        &self,
        plan: super::geodata::GeoUpdatePlan,
        reservation: Reservation,
    ) -> Result<(), ApiError> {
        self.enqueue(Work::GeoUpdate {
            plan: Box::new(plan),
            reservation,
        })
    }
    pub(crate) fn running(&self) -> bool {
        self.sources.available() && self.sender.lock().is_some()
    }
    pub(crate) fn attach_phase(
        &self,
        phase: tokio::sync::watch::Receiver<crate::control::EnginePhase>,
    ) {
        *self.phase.write() = Some(phase);
    }
    fn engine_phase(&self) -> Option<crate::control::EnginePhase> {
        self.phase.read().as_ref().map(|phase| *phase.borrow())
    }
    pub(crate) fn last_reload(&self) -> Option<Value> {
        self.last_reload.read().clone()
    }

    /// The secret set for `accepted`, rebuilt only when its sources are a new `SourceUpdate`.
    pub(crate) fn secrets(&self, accepted: Option<&Accepted>) -> Arc<ListenerSecrets> {
        let Some(accepted) = accepted else {
            return Arc::new(
                ListenerSecrets::new(&[], &self.settings.secret).with_secret(&self.clash_secret),
            );
        };
        let mut cached = self.secrets.lock();
        if let Some((update, secrets)) = cached.as_ref()
            && Arc::ptr_eq(update, &accepted.update)
        {
            return Arc::clone(secrets);
        }
        let mut secrets = ListenerSecrets::new(&accepted.update.sources, &self.settings.secret)
            .with_secret(&self.clash_secret);
        // Db sources are stripped, so the stored values are the only record of them.
        if let Some(SourceStore::Db(database)) = &*self.store.read() {
            secrets = secrets.with_all(&database.listener_secrets());
        }
        let secrets = Arc::new(secrets);
        *cached = Some((Arc::clone(&accepted.update), Arc::clone(&secrets)));
        secrets
    }

    /// The secret set for the sources accepted now.
    pub(crate) fn current_secrets(&self) -> Arc<ListenerSecrets> {
        self.secrets(self.sources.accepted.read().as_ref())
    }

    /// Every listener secret a response about `active` must not carry: each accepted declaration
    /// and stored value, and the effective secrets `active` runs with.
    pub(crate) fn secrets_with(&self, active: &Config) -> ListenerSecrets {
        self.current_secrets().as_ref().clone().with_config(active)
    }

    fn source_writable(&self, accepted: &Accepted, index: usize) -> bool {
        self.source_refusal(accepted, index).is_none()
    }

    /// Why the accepted source at `index` takes no write; `None` when it does.
    fn source_refusal(&self, accepted: &Accepted, index: usize) -> Option<WriteRefusal> {
        let secrets = self.secrets(Some(accepted));
        self.source_refusal_with_secrets(accepted, index, &secrets)
    }

    fn source_refusal_with_secrets(
        &self,
        accepted: &Accepted,
        index: usize,
        secrets: &ListenerSecrets,
    ) -> Option<WriteRefusal> {
        let source = &accepted.update.sources[index];
        if !self.settings.config_write || !self.settings.credentialed() {
            Some(WriteRefusal::WritesDisabled)
        } else if source.contains_api_secret {
            Some(WriteRefusal::ListenerSecretSource)
        } else if secrets.contains(&source.content) {
            Some(WriteRefusal::ListenerSecretInContent)
        } else {
            None
        }
    }

    /// Why the listed source at `index` is read-only in the accepted snapshot; `None` when it is
    /// writable.
    fn read_only_reason(
        &self,
        accepted: &Accepted,
        index: usize,
        secrets: &ListenerSecrets,
    ) -> Option<WriteRefusal> {
        match self.source_refusal_with_secrets(accepted, index, secrets) {
            refusal @ Some(WriteRefusal::WritesDisabled) => refusal,
            _ if self.store_blocked() => Some(WriteRefusal::StoreBlocked),
            refusal => refusal,
        }
    }

    /// Warns once per accepted snapshot about each source that a listener secret value in its text
    /// makes read-only; the fix is a secret no source contains.
    pub(crate) fn warn_secret_collisions(&self) {
        let guard = self.sources.accepted.read();
        let Some(accepted) = guard.as_ref() else {
            return;
        };
        {
            let mut warned = self.warned.lock();
            if warned.as_ref().is_some_and(|(update, generation)| {
                Arc::ptr_eq(update, &accepted.update) && *generation == accepted.generation
            }) {
                return;
            }
            *warned = Some((Arc::clone(&accepted.update), accepted.generation));
        }
        let secrets = self.secrets(Some(accepted));
        for (index, source) in accepted.update.sources.iter().enumerate() {
            if secrets.contains(&source.content) {
                tracing::warn!(
                    source_id = %accepted.ids[&source.path],
                    path = %secrets.mask(&source_path(accepted, index).to_string_lossy()).0,
                    "configuration source is read-only because its text contains a listener secret value"
                );
            }
        }
    }

    pub(crate) fn group_writable(&self, name: &str) -> bool {
        self.editable()
            && self
                .sources
                .accepted
                .read()
                .as_ref()
                .is_some_and(|accepted| {
                    accepted
                        .group_sources
                        .get(name)
                        .is_some_and(|index| self.source_writable(accepted, *index))
                })
    }

    pub(super) fn enqueue_group_patch(
        &self,
        patch: super::groups::GroupPatch,
        reservation: Reservation,
    ) -> Result<(), ApiError> {
        self.enqueue(Work::GroupPatch {
            patch: Box::new(patch),
            reservation,
        })
    }

    pub(crate) fn rule_source(&self, index: Option<usize>) -> Option<LocatedRule> {
        self.located_rule(|sources| match index {
            Some(index) => sources.rules.get(index),
            None => sources.fallback.as_ref(),
        })
    }

    /// `response` selects the DNS response list; `None` is that list's fallback.
    pub(crate) fn dns_rule_source(
        &self,
        response: bool,
        index: Option<usize>,
    ) -> Option<LocatedRule> {
        self.located_rule(|sources| {
            let list = if response {
                &sources.dns_response
            } else {
                &sources.dns_request
            };
            match index {
                Some(index) => list.rules.get(index),
                None => list.fallback.as_ref(),
            }
        })
    }

    fn located_rule(
        &self,
        pick: impl FnOnce(
            &honk_config::parser::source_edit::RuleSourceIndex,
        ) -> Option<&honk_config::parser::source_edit::RuleSourceLocation>,
    ) -> Option<LocatedRule> {
        let guard = self.sources.accepted.read();
        let accepted = guard.as_ref()?;
        let location = pick(&accepted.rule_sources)?;
        let source = &accepted.update.sources[location.source_index];
        let secrets = self.secrets(Some(accepted));
        let mut location = location.clone();
        location.expression = secrets.mask(&location.expression).0;
        Some((
            accepted.ids[&source.path].clone(),
            secrets
                .mask(&source_path(accepted, location.source_index).to_string_lossy())
                .0,
            location,
        ))
    }

    fn source_value(
        &self,
        accepted: &Accepted,
        index: usize,
        secrets: &ListenerSecrets,
    ) -> (Value, bool) {
        let source = &accepted.update.sources[index];
        let (content, mut redacted) = secrets.mask(&source.content);
        let (path, path_redacted) = secrets.mask(&source_path(accepted, index).to_string_lossy());
        let read_only_reason = self.read_only_reason(accepted, index, secrets);
        let mut value = json!({
            "id":accepted.ids[&source.path], "path":path,
            "kind":if index==0 {"main"} else {"include"},
            "content_sha256":accepted.hashes[index], "bytes":source.content.len(),
            "writable":read_only_reason.is_none(), "loaded_at":timestamp(accepted.accepted_at),
            "line_count":source.content.lines().count(), "content":content,
        });
        if let Some(reason) = read_only_reason {
            value["read_only_reason"] = json!(reason.as_str());
        }
        // Database source paths are labels, not files an operator could open.
        if !matches!(*self.store.read(), Some(SourceStore::Db(_))) {
            let (absolute_path, absolute_redacted) = secrets.mask(&source.path.to_string_lossy());
            value["absolute_path"] = Value::String(absolute_path);
            redacted |= absolute_redacted;
        }
        (value, redacted || path_redacted)
    }

    pub(crate) fn snapshot(&self) -> Option<Value> {
        let guard = self.sources.accepted.read();
        let accepted = guard.as_ref()?;
        let secrets = self.secrets(Some(accepted));
        let mut secrets_redacted = false;
        let sources = (0..accepted.update.sources.len())
            .map(|index| {
                let (value, redacted) = self.source_value(accepted, index, &secrets);
                secrets_redacted |= redacted;
                value
            })
            .collect::<Vec<_>>();
        Some(
            json!({"generation_id":format!("{}:{}",self.instance_id,accepted.generation),"revision":accepted.revision,
            "sources":sources,"diagnostics":[],"secrets_redacted":secrets_redacted}),
        )
    }

    /// Only validation runs while the engine is not running.
    fn check_phase(&self, work: &Work) -> Result<(), ApiError> {
        if matches!(work, Work::Validate { .. })
            || self.engine_phase() == Some(crate::control::EnginePhase::Running)
        {
            return Ok(());
        }
        Err(unavailable())
    }

    /// A dropped `Work` drops its reservation, which rejects the operation as unavailable.
    fn enqueue(&self, work: Work) -> Result<(), ApiError> {
        self.check_phase(&work)?;
        self.sender
            .lock()
            .as_ref()
            .ok_or_else(unavailable)?
            .try_send(work)
            .map_err(|_| unavailable())
    }

    pub(crate) fn request_sighup(&self) -> Result<(), ApiError> {
        self.enqueue(Work::Sighup)
    }
}

/// Reserves the operation and queues `work` for a fresh reservation; a replay awaits the original.
async fn admit(
    state: &NativeState,
    method: &str,
    path: &str,
    key: Option<&str>,
    bytes: &[u8],
    work: impl FnOnce(Reservation) -> Work,
) -> Result<Response, ApiError> {
    let service = &state.observation.configuration;
    let reservation = service.operations.reserve(
        state.principal(),
        method,
        path,
        key,
        bytes,
        super::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        service.enqueue(work(reservation))?;
    }
    Ok(admission.await?.into_response())
}

fn same_source_documents(left: &[SourceSnapshot], right: &[SourceSnapshot]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.path == right.path && left.parent == right.parent && left.content == right.content
        })
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Configuration coordinator is unavailable",
        None,
    )
}
pub(super) fn denied() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::PermissionDenied,
        "Configuration administration is not permitted",
        None,
    )
}
fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Configuration source was not found",
        None,
    )
}
fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::RequestTooLarge,
        "Configuration source budget exceeded",
        None,
    )
}
fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Configuration sources are unavailable",
        None,
    )
}
pub(super) fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid configuration request",
        None,
    )
}
fn exists() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "A configuration source already exists at this path",
        None,
    )
}
fn changed() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "Configuration changed during the write",
        None,
    )
}
fn stale() -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        ErrorCode::StaleRevision,
        "Configuration changed on disk",
        None,
    )
}

pub(super) fn request_header<'a>(
    request: &'a Request,
    name: &str,
) -> Result<Option<&'a str>, ApiError> {
    let rejected = |kind| invalid().with_details(json!({"header": name, "kind": kind}));
    let mut values = request.headers().get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(rejected("duplicate"));
    }
    first
        .map(|value| value.to_str().map_err(|_| rejected("not_text")))
        .transpose()
}
/// An `If-Match` condition evaluated as RFC 9110 §13.1.1 defines. Weak tags are dropped on
/// parsing because they never match.
#[derive(Clone, Debug)]
pub(super) enum IfMatch {
    Any,
    Tags(Vec<String>),
}

impl IfMatch {
    /// Reads every `If-Match` field line as one list; `None` when the header is absent.
    pub(super) fn from_request(request: &Request) -> Result<Option<Self>, ApiError> {
        let rejected = |kind| invalid().with_details(json!({"header":"if-match","kind":kind}));
        let mut lines = Vec::new();
        for value in request.headers().get_all("if-match") {
            lines.push(value.to_str().map_err(|_| rejected("not_text"))?);
        }
        if lines.is_empty() {
            return Ok(None);
        }
        Self::parse(&lines.join(","))
            .map(Some)
            .ok_or_else(|| rejected("malformed"))
    }

    fn parse(value: &str) -> Option<Self> {
        const OWS: [char; 2] = [' ', '\t'];
        let mut rest = value.trim_matches(OWS);
        if rest == "*" {
            return Some(Self::Any);
        }
        // An empty value, or one made only of empty list elements, is not a list of tags.
        let mut elements = 0;
        let mut tags = Vec::new();
        while !rest.is_empty() {
            if let Some(next) = rest.strip_prefix(',') {
                rest = next.trim_start_matches(OWS);
                continue;
            }
            let weak = rest.starts_with("W/");
            let quoted = rest.strip_prefix("W/").unwrap_or(rest).strip_prefix('"')?;
            let end = quoted.find('"')?;
            let opaque = &quoted[..end];
            if !opaque.bytes().all(|byte| byte.is_ascii_graphic()) {
                return None;
            }
            rest = quoted[end + 1..].trim_start_matches(OWS);
            if !rest.is_empty() && !rest.starts_with(',') {
                return None;
            }
            elements += 1;
            if !weak {
                tags.push(opaque.to_owned());
            }
        }
        (elements > 0).then_some(Self::Tags(tags))
    }

    /// Whether the condition holds for an existing resource whose strong tag is `current`.
    pub(super) fn matches(&self, current: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Tags(tags) => tags.iter().any(|tag| tag == current),
        }
    }
}

pub(super) fn json_type(request: &Request) -> Result<(), ApiError> {
    if request_header(request, "content-type")?
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json",
            None,
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationSource {
    id: Option<String>,
    path: Option<String>,
    content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationRequest {
    sources: Vec<ValidationSource>,
    mode: String,
}

fn project_diagnostic(
    diagnostic: &DetailedDiagnostic,
    sources: &[SourceSnapshot],
    ids: &HashMap<PathBuf, String>,
    fallback: Option<&str>,
) -> Value {
    let source = sources
        .iter()
        .find(|source| source.source.same_source(&diagnostic.source));
    let metadata = diagnostic.source.sources().metadata();
    let mapped = source.and_then(|source| ids.get(&source.path)).or_else(|| {
        fallback
            .and_then(|_| metadata.get(diagnostic.source.index())?.path.as_ref())
            .and_then(|path| ids.get(path))
    });
    let source_id = mapped
        .map(String::as_str)
        .or(fallback)
        .or_else(|| {
            sources
                .first()
                .and_then(|source| ids.get(&source.path))
                .map(String::as_str)
        })
        .unwrap_or("source-1");
    let exact = mapped.is_some();
    json!({"level":match diagnostic.severity{Severity::Error=>"error",Severity::Warning=>"warning",Severity::Info=>"info"},
        "source_id":source_id,"line":if exact{diagnostic.line}else{None},"column":if exact{diagnostic.byte_column}else{None},
        "span":null,"code":diagnostic.code,"message":diagnostic.message})
}

/// A new source path as clients spell it: relative normal segments naming a `.dae` file.
fn new_source_path(label: &str) -> bool {
    label.len() <= 1024
        && label.ends_with(".dae")
        && !label.chars().any(char::is_control)
        && label
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

pub(super) fn resolve_source_path(root: &Path, label: &str) -> Result<PathBuf, ApiError> {
    let input = Path::new(label);
    let path = if input.is_absolute() {
        input.strip_prefix(root).map_err(|_| invalid())?
    } else {
        input
    };
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
        || path.extension().and_then(|value| value.to_str()) != Some("dae")
    {
        return Err(invalid());
    }
    let joined = root.join(path);
    let resolved = if joined.exists() {
        std::fs::canonicalize(&joined).map_err(|_| unavailable())?
    } else {
        let parent =
            std::fs::canonicalize(joined.parent().ok_or_else(invalid)?).map_err(|_| invalid())?;
        parent.join(joined.file_name().ok_or_else(invalid)?)
    };
    if !resolved.starts_with(root) {
        return Err(invalid());
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests;
