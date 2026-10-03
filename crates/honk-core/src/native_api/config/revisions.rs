//! Export, import and the revision list of the configuration db.

use axum::http::{HeaderValue, header};
use honk_config::parser::source_edit::{inline_sources, strip_listener_secrets};

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    replace: bool,
}

pub(in crate::native_api) async fn export(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let config = state.config.read().await;
    let service = &state.observation.configuration;
    let accepted = service.sources.accepted.read().clone().ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Configuration sources are unavailable",
            id,
        )
    })?;
    let mut omitted = matches!(*service.store.read(), Some(SourceStore::Db(_)))
        && !(config.experimental.native_api.secret.is_empty()
            && config.experimental.clash_api.secret.is_empty());
    let mut sources = accepted.update.sources.clone();
    for source in &mut sources {
        let stripped = strip_listener_secrets(&source.content).map_err(|_| unavailable())?;
        omitted |= stripped != source.content.as_ref();
        source.content = Arc::from(stripped);
    }
    let inlined = inline_sources(&sources).map_err(|_| unavailable())?;
    let (inlined, _) = service
        .secrets(Some(&accepted))
        .as_ref()
        .clone()
        .with_config(&config)
        .mask(&inlined);
    let body = if omitted {
        format!("# listener secrets omitted\n{inlined}")
    } else {
        inlined
    };
    let store = service.store_value();
    let filename = match store["revision"].as_i64() {
        Some(revision) if store["recorded"] == true => format!("honk-r{revision}.dae"),
        _ => "honk.dae".to_owned(),
    };
    let etag = format!("\"{}\"", crate::configuration::digest(body.as_bytes()));
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|_| unavailable())?,
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|_| unavailable())?,
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(in crate::native_api) async fn revisions(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let service = &state.observation.configuration;
    let Some(SourceStore::Db(store)) = service.store.read().clone() else {
        return Err(unsupported());
    };
    let store_error = || unavailable().with_details(json!({"stage":"store"}));
    let (active, rows) = tokio::task::spawn_blocking(move || store.revisions())
        .await
        .map_err(|_| store_error())?
        .map_err(|_| store_error())?;
    let secrets = service.current_secrets();
    let revisions: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let created_at = std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(u64::try_from(row.created_at).unwrap_or(0));
            json!({
                "revision":row.number, "parent":row.parent, "created_at":timestamp(created_at),
                "principal":row.principal, "origin":row.origin, "content_sha256":row.content_sha256,
                "bytes":row.bytes,
                "sources":row.sources.iter().map(|(path,sha256)|json!({"path":secrets.mask(path).0,"sha256":sha256})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(
        Json(json!({"active":active,"max_revisions":MAX_REVISIONS,"revisions":revisions}))
            .into_response(),
    )
}

pub(in crate::native_api) async fn import(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let service = &state.observation.configuration;
    let Some(SourceStore::Db(store)) = service.store.read().clone() else {
        return Err(unsupported());
    };
    if let Some(reason) = service.write_refusal() {
        return Err(denied().with_reason(reason));
    }
    json_type(&request)?;
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    let key = key.ok_or_else(precondition_required)?;
    let bytes = body::buffered(request.into_body()).await;
    let body: Import = body::decode(&bytes, invalid)?;
    let initialized = store.cached_head().is_some();
    if initialized && !body.replace {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::StateConflict,
            "The configuration db already holds a revision; send replace to overwrite it",
            None,
        ));
    }
    admit(
        state,
        "POST",
        "/api/v1/x-honk/config/import",
        Some(&key),
        &bytes,
        |reservation| Work::Import { reservation },
    )
    .await
}

pub(in crate::native_api) async fn activate(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let service = &state.observation.configuration;
    let Some(SourceStore::Db(store)) = service.store.read().clone() else {
        return Err(unsupported());
    };
    if let Some(reason) = service.write_refusal() {
        return Err(denied().with_reason(reason));
    }
    let path = request.uri().path().to_owned();
    let number = path
        .strip_suffix("/activate")
        .and_then(|rest| rest.rsplit('/').next())
        .and_then(|number| number.parse::<i64>().ok())
        .ok_or_else(not_found)?;
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    if request.body().size_hint().upper() != Some(0) {
        json_type(&request)?;
    }
    let bytes = body::buffered(request.into_body()).await;
    body::no_inputs(&bytes, invalid)?;
    // A replay answers even after retention pruned the revision.
    let reservation = service.operations.reserve(
        state.principal(),
        "POST",
        &path,
        key.as_deref(),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let exists = tokio::task::spawn_blocking(move || store.revision_exists(number))
            .await
            .map_err(|_| unavailable())?;
        let error = match exists {
            Ok(true) => None,
            Ok(false) => Some(not_found()),
            Err(_) => Some(unavailable().with_details(json!({"stage":"store"}))),
        };
        match error {
            None => service.enqueue(Work::ActivateRevision {
                number,
                reservation,
            })?,
            Some(error) => {
                service.operations.reject(&reservation.id, error);
            }
        }
    }
    Ok(admission.await?.into_response())
}

fn precondition_required() -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_REQUIRED,
        ErrorCode::PreconditionRequired,
        "Idempotency-Key is required",
        None,
    )
}
