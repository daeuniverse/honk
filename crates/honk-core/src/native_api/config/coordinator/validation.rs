use super::*;
use honk_config::parser::{check_dae_source, parse_dae_sources};

impl Worker {
    pub(super) async fn validate(&self, request: ValidationRequest) -> Result<Value, ApiError> {
        let active = self.active.read().await.clone();
        let log_files = self.log_files.clone();
        let startup_downgrades = self.startup_downgrades.clone();
        let generation = self.diagnostics.read().generation;
        let instance = self.service.instance_id.clone();
        let store = self.store.clone();
        let accepted = self.service.sources.accepted.read().clone();
        let data_dir = self.data_dir.clone();
        let deferred = if request.mode == "syntax" {
            Vec::new()
        } else {
            self.subscriptions
                .deferred_subscriptions()
                .await
                .map_err(|_| unavailable())?
        };
        tokio::task::spawn_blocking(move||{
            let entry=store.entry().to_path_buf();
            let mut documents=Vec::new();let mut ids=HashMap::new();
            for (index,source) in request.sources.iter().enumerate(){
                let path=source.path.as_deref();
                let resolved=if request.mode=="syntax" {PathBuf::from(path.map(str::to_owned).unwrap_or_else(||format!("source-{}.dae",index+1)))}
                    else if index==0 {
                        if let Some(path)=path {let supplied=store.resolve(path)?;if supplied!=entry{return Err(invalid());}}
                        entry.clone()
                    }else if let Some(path)=path { store.resolve(path)? }
                    else if let Some(path)=source.id.as_ref().and_then(|id|accepted.as_ref()?.ids.iter().find(|(_,value)|*value==id).map(|(path,_)|path.clone())) { path }
                    else { entry.parent().ok_or_else(invalid)?.join(format!("source-{}.dae",index+1)) };
                if ids.insert(resolved.clone(),source.id.clone().unwrap_or_else(||format!("source-{}",index+1))).is_some(){return Err(invalid());}
                documents.push((resolved,Arc::<str>::from(source.content.as_str())));
            }
            let mut diagnostics=Vec::new();
            let mut initial_sources=Vec::new();
            let result=if request.mode=="syntax" {parse_dae_sources(&documents,SourceLimits::DEFAULT,&mut diagnostics)}
                else {(||{
                    let overlay=documents.iter().cloned().collect();
                    let loaded=store.load(&overlay,&mut diagnostics)?;
                    initial_sources=loaded.sources.clone();
                    for (path,content) in &documents {
                        if !loaded.sources.iter().any(|source|source.path==*path) {
                            check_dae_source(path,content)?;
                        }
                    }
                    let validated=offline::validate_for_coordinator(loaded,store.dependency_root(),&active,&data_dir,SourceLimits::DEFAULT,&mut diagnostics,&deferred,None,&documents)?;
                    // A save of this candidate would be refused; a dry run only warns.
                    diagnostics.extend(restart_diagnostics(&active,&validated.config,&log_files,&startup_downgrades,&validated.sources[0].source,Severity::Warning));
                    Ok(LoadedConfig {config:validated.config,sources:validated.sources})
                })()};
            if let Err(error)=&result {
                if is_limit(error){return Err(too_large());}
                if !diagnostics.iter().any(|diagnostic|diagnostic==error.diagnostic.as_ref()){diagnostics.push(error.diagnostic.as_ref().clone());}
            }
            let sources=result.as_ref().map(|loaded|loaded.sources.as_slice()).unwrap_or(&initial_sources);
            let main_id=ids.get(&documents[0].0).map(String::as_str);
            let projected=diagnostics.iter().map(|diagnostic|project_diagnostic(diagnostic,sources,&ids,main_id)).collect::<Vec<_>>();
            Ok(json!({"valid":result.is_ok()&&!diagnostics.iter().any(|row|row.severity==Severity::Error),"diagnostics":projected,
                "generation_id":format!("{instance}:{generation}"),"validated_at":timestamp(SystemTime::now())}))
        }).await.map_err(|_|unavailable())?
    }

    pub(super) async fn candidate_check(&self) -> Result<CandidateCheck, ApiError> {
        let active = self.active.read().await.clone();
        Ok(CandidateCheck {
            store: self.store.clone(),
            secrets: self.service.secrets_with(&active),
            active,
            log_files: self.log_files.clone(),
            startup_downgrades: self.startup_downgrades.clone(),
            data_dir: self.data_dir.clone(),
            deferred: self
                .subscriptions
                .deferred_subscriptions()
                .await
                .map_err(|_| unavailable())?,
        })
    }
}

/// What a candidate validates against, captured before blocking work.
pub(super) struct CandidateCheck {
    pub(super) store: SourceStore,
    /// The set the source listing's `writable` uses, so a write it offers is not refused here.
    pub(super) secrets: ListenerSecrets,
    pub(super) active: Arc<Config>,
    pub(super) log_files: LogFiles,
    pub(super) startup_downgrades: StartupDowngrades,
    pub(super) data_dir: PathBuf,
    pub(super) deferred: Vec<honk_config::subscription::Subscription>,
}

impl CandidateCheck {
    /// Full validation of a candidate, refusing anything the write or the following reload
    /// must not admit. `write` is a source write of `content` at `target` over `accepted`;
    /// `None` is a whole-tree candidate.
    pub(super) fn validate(
        &self,
        loaded: LoadedConfig,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        write: Option<(&Accepted, &Path, &str)>,
        fallback: Option<&str>,
        ids: Option<&HashMap<PathBuf, String>>,
    ) -> Result<offline::ValidatedConfig, ApiError> {
        let active = &self.active;
        let parsed_sources = loaded.sources.clone();
        let validated = offline::validate_for_coordinator(
            loaded,
            self.store.dependency_root(),
            active,
            &self.data_dir,
            SourceLimits::DEFAULT,
            diagnostics,
            &self.deferred,
            None,
            &[],
        )
        .map_err(|error| config_error(error, diagnostics, &parsed_sources, fallback, ids))?;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            return Err(diagnostics_error(
                diagnostics,
                &validated.sources,
                fallback,
                ids,
            ));
        }
        let mut written = &validated.sources[0];
        let refusal = if let Some((accepted, target, content)) = write {
            let old_credentials: Vec<_> = accepted
                .update
                .sources
                .iter()
                .filter(|source| source.contains_api_secret)
                .map(|source| (&source.path, &source.content))
                .collect();
            let new_credentials: Vec<_> = validated
                .sources
                .iter()
                .filter(|source| source.contains_api_secret)
                .map(|source| (&source.path, &source.content))
                .collect();
            // The target's own declaration implies a changed credential set, so it goes first.
            let refusal = if validated
                .sources
                .iter()
                .any(|source| source.path == target && source.contains_api_secret)
            {
                Some(WriteRefusal::ListenerSecretSource)
            } else if self.secrets.contains(content) {
                Some(WriteRefusal::ListenerSecretInContent)
            } else if old_credentials != new_credentials {
                Some(WriteRefusal::CredentialSourcesChanged)
            } else {
                None
            };
            if let Some(source) = validated
                .sources
                .iter()
                .find(|source| source.path == target)
            {
                written = source;
            }
            refusal
        } else {
            None
        };
        let refusal = refusal.or_else(|| {
            (validated.config.experimental.native_api != active.experimental.native_api
                || validated.config.experimental.clash_api.secret
                    != active.experimental.clash_api.secret
                || (matches!(self.store, SourceStore::Db(_))
                    && validated.config.global.data_dir != active.global.data_dir))
                .then_some(WriteRefusal::ListenerSettingsChanged)
        });
        if let Some(reason) = refusal {
            return Err(denied().with_reason(reason));
        }
        // The reload would reject these, and a rejected reload leaves the written file
        // ahead of the accepted hash; refuse before writing.
        let restart = restart_diagnostics(
            active,
            &validated.config,
            &self.log_files,
            &self.startup_downgrades,
            &written.source,
            Severity::Error,
        );
        if !restart.is_empty() {
            diagnostics.extend(restart);
            return Err(diagnostics_error(
                diagnostics,
                &validated.sources,
                fallback,
                ids,
            ));
        }
        Ok(validated)
    }

    pub(super) fn recheck(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        validated: &offline::ValidatedConfig,
    ) -> Result<(), WriteError> {
        unchanged(
            &self.store,
            overlay,
            validated,
            &self.active,
            &self.data_dir,
            &self.deferred,
        )
    }
}

/// Fails with `Conflict` unless `store` still yields `validated`: the same documents, loading
/// without errors, over the same dependencies.
pub(super) fn unchanged(
    store: &SourceStore,
    overlay: &HashMap<PathBuf, Arc<str>>,
    validated: &offline::ValidatedConfig,
    active: &Config,
    data_dir: &Path,
    deferred: &[honk_config::subscription::Subscription],
) -> Result<(), WriteError> {
    let mut notices = Vec::new();
    let loaded = store
        .load(overlay, &mut notices)
        .map_err(|_| WriteError::Conflict)?;
    if notices
        .iter()
        .any(|notice| notice.severity == Severity::Error)
        || !same_source_documents(&validated.sources, &loaded.sources)
    {
        return Err(WriteError::Conflict);
    }
    let dependencies = validated
        .recapture_dependencies(active, data_dir, SourceLimits::DEFAULT, deferred)
        .map_err(|_| WriteError::Conflict)?;
    if validated.dependencies != dependencies {
        return Err(WriteError::Conflict);
    }
    Ok(())
}

/// Restart-only settings the candidate changes, as diagnostics on `source`. The reload
/// transaction rejects such a candidate, so a write must not start with one.
pub(super) fn restart_diagnostics(
    active: &Config,
    candidate: &Config,
    log_files: &LogFiles,
    startup_downgrades: &StartupDowngrades,
    source: &honk_config::diagnostic::SourceRef,
    severity: Severity,
) -> Vec<DetailedDiagnostic> {
    use honk_config::diagnostic::{SafeValue, SettingPath, SettingSegment};

    crate::control::restart_required_fields(active, candidate, log_files, startup_downgrades)
        .into_iter()
        .map(|field| {
            let mut diagnostic = DetailedDiagnostic::warning(
                "restart-required",
                source.clone(),
                SettingPath(field.path.split('.').map(SettingSegment::Field).collect()),
                SafeValue::Empty,
                field.message,
            );
            diagnostic.severity = severity;
            diagnostic
        })
        .collect()
}

fn is_limit(error: &honk_config::error::DetailedConfigError) -> bool {
    matches!(
        error.diagnostic.code,
        "config-source-limit"
            | "config-byte-limit"
            | "dependency-byte-limit"
            | "dependency-source-limit"
    )
}
pub(super) fn diagnostics_error(
    diagnostics: &[DetailedDiagnostic],
    sources: &[SourceSnapshot],
    fallback: Option<&str>,
    accepted_ids: Option<&HashMap<PathBuf, String>>,
) -> ApiError {
    let generated = sources
        .iter()
        .enumerate()
        .map(|(index, source)| (source.path.clone(), format!("source-{}", index + 1)))
        .collect();
    let ids = accepted_ids.unwrap_or(&generated);
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY,ErrorCode::UnsupportedValue,"Configuration validation failed",None)
        .with_details(json!({"diagnostics":diagnostics.iter().map(|diagnostic|project_diagnostic(diagnostic,sources,ids,fallback)).collect::<Vec<_>>()}))
}
/// A created path that no include pattern of the candidate loads.
pub(super) fn not_included(main: &str) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY,ErrorCode::UnsupportedValue,"Configuration validation failed",None)
        .with_details(json!({"diagnostics":[{"level":"error","source_id":main,"line":null,"column":null,"span":null,
            "code":"source-not-included","message":"No include pattern loads this path."}]}))
}
pub(super) fn config_error(
    error: honk_config::error::DetailedConfigError,
    diagnostics: &[DetailedDiagnostic],
    sources: &[SourceSnapshot],
    fallback: Option<&str>,
    ids: Option<&HashMap<PathBuf, String>>,
) -> ApiError {
    if is_limit(&error) {
        return too_large();
    }
    let mut all = diagnostics.to_vec();
    if !all.iter().any(|row| row == error.diagnostic.as_ref()) {
        all.push(*error.diagnostic);
    }
    diagnostics_error(&all, sources, fallback, ids)
}
