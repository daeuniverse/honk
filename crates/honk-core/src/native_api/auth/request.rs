//! Password-mode HTTP requests.

use super::storage::SetupError;
use super::{Auth, Issued, RECORD_LIMIT, valid_password, valid_username};
use axum::Json;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::native_api::types::RequestId;

use crate::native_api::{ApiError, ErrorCode, NativeState, Peer, body, error};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    password: String,
}

/// The listener runs in password mode, or these endpoints do not exist.
fn required<'a>(state: &'a NativeState, id: &RequestId) -> Result<&'a Arc<Auth>, ApiError> {
    state.auth.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Password login is not enabled on this listener",
            Some(id.0.clone()),
        )
    })
}

async fn credentials(request: Request, id: &RequestId) -> Result<Credentials, ApiError> {
    crate::native_api::config::json_type(&request)
        .map_err(|error| error.with_request_id(id.0.clone()))?;
    if request.uri().query().is_some() {
        return Err(invalid(id));
    }
    // The boundary has already read the body into memory and bounded its size.
    let bytes = axum::body::to_bytes(request.into_body(), RECORD_LIMIT)
        .await
        .map_err(|_| invalid(id).with_details(body::too_large()))?;
    let credentials: Credentials = body::decode(&bytes, || invalid(id))?;
    if !valid_username(&credentials.username) || !valid_password(&credentials.password) {
        return Err(invalid(id));
    }
    Ok(credentials)
}

fn invalid(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Credentials require a username and a password of 8 to 128 characters",
        Some(id.0.clone()),
    )
}

/// One shape for a wrong username and a wrong password, so neither can be probed.
fn rejected(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        ErrorCode::InvalidCredentials,
        "Username or password is not correct",
        Some(id.0.clone()),
    )
}

fn issued(session: Issued) -> Response {
    let expires_at = crate::observe::timestamp(session.expires_at);
    Json(json!({"token": session.token, "expires_at": expires_at})).into_response()
}

/// Claims the one administrator account. Only a loopback or private peer may do this, and only while
/// no account exists; deriving the peer from a header would let anyone claim it through a proxy.
pub(crate) async fn setup(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    let result = async {
        let auth = required(&state, &id)?;
        let peer = *request
            .extensions()
            .get::<Peer>()
            .ok_or_else(|| forbidden_setup(&id))?;
        if !peer.may_set_up() {
            return Err(forbidden_setup(&id));
        }
        let credentials = credentials(request, &id).await;
        auth.run(peer, &id, move |auth, id| {
            if !auth.store.setup_required() {
                return Err(already_completed(id));
            }
            let credentials = credentials?;
            match auth
                .store
                .setup(&credentials.username, &credentials.password)
            {
                Ok(()) => {
                    auth.rate.succeeded();
                    Ok((StatusCode::CREATED, issued(auth.sessions.issue())).into_response())
                }
                Err(SetupError::AlreadyCompleted) => Err(already_completed(id)),
                Err(SetupError::NotDurable) => Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::TemporarilyUnavailable,
                    "The administrator record's durability could not be confirmed",
                    Some(id.0.clone()),
                )
                .with_details(json!({"durability_confirmed": false}))
                .without_retry_after()),
                Err(SetupError::Unavailable) => Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::TemporarilyUnavailable,
                    "The administrator record could not be written",
                    Some(id.0.clone()),
                )),
            }
        })
        .await
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

fn already_completed(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::SetupAlreadyCompleted,
        "An administrator already exists",
        Some(id.0.clone()),
    )
}

fn forbidden_setup(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::PermissionDenied,
        "Administrator setup is allowed from loopback and private addresses only",
        Some(id.0.clone()),
    )
}

pub(crate) async fn login(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    let result = async {
        let auth = required(&state, &id)?;
        let peer = *request
            .extensions()
            .get::<Peer>()
            .ok_or_else(|| rejected(&id))?;
        let credentials = credentials(request, &id).await;
        auth.run(peer, &id, move |auth, id| {
            if auth.store.setup_required() {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::SetupRequired,
                    "No administrator exists yet",
                    Some(id.0.clone()),
                ));
            }
            let credentials = credentials?;
            if !auth
                .store
                .verify(&credentials.username, &credentials.password)
            {
                auth.rate.failed();
                return Err(rejected(id));
            }
            auth.rate.succeeded();
            Ok(issued(auth.sessions.issue()))
        })
        .await
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

pub(crate) async fn logout(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        return error(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Password login is not enabled on this listener",
            &id,
        )
        .into_response();
    };
    if let Some(token) = state.security_bearer(&request) {
        auth.sessions.revoke(token);
    }
    StatusCode::NO_CONTENT.into_response()
}
