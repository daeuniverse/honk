//! Shared HTTP boundary for the native API and its public static UI.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, HttpBody};
use axum::extract::{MatchedPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::BytesMut;
use futures::StreamExt;
use futures::future::poll_fn;
use honk_config::experimental::{NativeApiConfig, parse_native_authority, parse_native_origin};
use serde::de::IgnoredAny;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::NativeState;
use super::auth::SessionLease;
use super::types::{Admitted, ApiError, ErrorCode, RequestId, WriteRefusal};

pub(super) const MAX_TARGET_BYTES: usize = 4096;
pub(super) const MAX_HEADER_BYTES: usize = 16384;
pub(super) const MAX_BODY_BYTES: usize = 65536;
const ALLOW_HEADERS: &str =
    "Authorization, Last-Event-ID, Content-Type, If-Match, Idempotency-Key, Accept";

/// Admissions per minute through one `RequestRate`, as capabilities advertise it.
pub(crate) const REQUESTS_PER_MINUTE: u32 = 30;

pub(crate) struct RequestRate(parking_lot::Mutex<(Instant, u32)>);

impl RequestRate {
    pub(crate) fn new() -> Self {
        Self(parking_lot::Mutex::new((Instant::now(), 0)))
    }

    pub(super) fn admit(&self, id: &RequestId) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut window = self.0.lock();
        let elapsed = now.duration_since(window.0);
        if elapsed >= std::time::Duration::from_secs(60) {
            *window = (now, 0);
        }
        if window.1 == REQUESTS_PER_MINUTE {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::RateLimited,
                "Request rate limit reached",
                Some(id.0.clone()),
            )
            .with_retry_after((60 - elapsed.as_secs()) as u32));
        }
        window.1 += 1;
        Ok(())
    }
}

pub(super) struct Security {
    expected: Option<[u8; 32]>,
    anonymous_loopback: bool,
    hosts: HashSet<(String, u16)>,
    origins: HashSet<(String, String, u16)>,
    /// The listen port when bound to an unspecified address: an IP-literal
    /// `Host` (or `localhost`) at that port is the listener itself, whatever
    /// interface the request arrived on. DNS names still need `allowed_hosts`,
    /// since only a name can be rebound to point at this listener.
    wildcard_port: Option<u16>,
}

impl Security {
    pub(super) fn new(config: &NativeApiConfig, listen: SocketAddr) -> Self {
        let mut hosts = HashSet::new();
        if !listen.ip().is_unspecified() {
            hosts.insert((listen.ip().to_string(), listen.port()));
        }
        if listen.ip().is_loopback() {
            for host in ["localhost", "127.0.0.1", "::1"] {
                hosts.insert((host.to_owned(), listen.port()));
            }
        }
        // Extra proxy Hosts do not establish a trustworthy scheme or Origin.
        let mut origins: HashSet<_> = hosts
            .iter()
            .map(|(host, port)| ("http".to_owned(), host.clone(), *port))
            .collect();
        hosts.extend(config.allowed_hosts.iter().map(|host| {
            parse_native_authority(host, 80).expect("validated native host authority")
        }));
        origins.extend(
            config
                .allow_origins
                .iter()
                .map(|origin| parse_native_origin(origin).expect("validated native origin")),
        );
        Self {
            expected: (!config.secret.is_empty())
                .then(|| Sha256::digest(config.secret.as_bytes()).into()),
            anonymous_loopback: config.secret.is_empty()
                && config.allow_anonymous_loopback
                && listen.ip().is_loopback(),
            hosts,
            origins,
            wildcard_port: listen.ip().is_unspecified().then_some(listen.port()),
        }
    }

    pub(super) fn anonymous_loopback(&self) -> bool {
        self.anonymous_loopback
    }

    /// The bearer token this request carries, if it is well formed.
    pub(super) fn bearer<'a>(&self, request: &'a Request) -> Option<&'a str> {
        single_header(request.headers(), "authorization")
            .ok()
            .flatten()?
            .to_str()
            .ok()?
            .split_once(' ')
            .filter(|(scheme, token)| {
                scheme.eq_ignore_ascii_case("Bearer")
                    && honk_config::experimental::valid_native_bearer_token(token)
            })
            .map(|(_, token)| token)
    }

    fn listener_itself(&self, host: &str, port: u16) -> bool {
        self.wildcard_port == Some(port)
            && (host == "localhost" || host.parse::<std::net::IpAddr>().is_ok())
    }

    fn host_allowed(&self, authority: &(String, u16)) -> bool {
        self.hosts.contains(authority) || self.listener_itself(&authority.0, authority.1)
    }

    // The plain-HTTP origin of the listener itself is as trustworthy as its Host, so on a
    // wildcard bind it must name that Host: another IP literal at the same port is another
    // site. An extra `allowed_hosts` entry says nothing about the scheme and needs
    // `allow_origins`.
    fn origin_allowed(&self, origin: &(String, String, u16), authority: &(String, u16)) -> bool {
        let (scheme, host, port) = origin;
        self.origins.contains(origin)
            || (scheme == "http"
                && (host, *port) == (&authority.0, authority.1)
                && self.listener_itself(host, *port))
    }

    fn check_origin(
        &self,
        headers: &HeaderMap,
        request_id: &str,
    ) -> Result<Option<HeaderValue>, ApiError> {
        let authority = single_header(headers, "host")
            .ok()
            .flatten()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_native_authority(value, 80))
            .filter(|authority| self.host_allowed(authority))
            .ok_or_else(|| forbidden(request_id))?;
        let origin = single_header(headers, "origin").map_err(|()| forbidden(request_id))?;
        if let Some(origin) = origin {
            let allowed = origin
                .to_str()
                .ok()
                .and_then(parse_native_origin)
                .is_some_and(|origin| self.origin_allowed(&origin, &authority));
            if !allowed {
                return Err(forbidden(request_id));
            }
        }
        if self.anonymous_loopback {
            let site =
                single_header(headers, "sec-fetch-site").map_err(|()| forbidden(request_id))?;
            if let Some(site) = site {
                let site = site.to_str().map_err(|_| forbidden(request_id))?;
                if site.eq_ignore_ascii_case("cross-site") {
                    return Err(forbidden(request_id));
                }
            }
        }
        Ok(origin.cloned())
    }

    fn authenticate(
        &self,
        request: &Request,
        sessions: Option<&super::auth::Sessions>,
        request_id: &str,
    ) -> Result<Option<SessionLease>, ApiError> {
        let authorization = single_header(request.headers(), "authorization")
            .map_err(|()| unauthorized(request_id))?;
        if let Some(sessions) = sessions {
            let lease = self
                .bearer(request)
                .and_then(|token| sessions.authenticate(token))
                .ok_or_else(|| unauthorized(request_id))?;
            self.reject_query_credentials(request, request_id)?;
            return Ok(Some(lease));
        }
        match (&self.expected, authorization) {
            (Some(expected), Some(_)) => {
                let token = self
                    .bearer(request)
                    .ok_or_else(|| unauthorized(request_id))?;
                let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
                if !bool::from(expected.ct_eq(&actual)) {
                    return Err(unauthorized(request_id));
                }
            }
            (None, None) if self.anonymous_loopback => {}
            _ => return Err(unauthorized(request_id)),
        }
        self.reject_query_credentials(request, request_id)?;
        Ok(None)
    }

    fn reject_query_credentials(
        &self,
        request: &Request,
        request_id: &str,
    ) -> Result<(), ApiError> {
        match query_credential(request) {
            None => Err(invalid_request(
                request_id,
                json!({"field":"query","kind":"malformed"}),
            )),
            Some(true) => Err(unauthorized(request_id)),
            Some(false) => Ok(()),
        }
    }
}

/// Whether the query names `token` or `access_token`, decoded with the same form parser as API
/// queries; `None` when the query is malformed.
fn query_credential(request: &Request) -> Option<bool> {
    let Query(parameters) = Query::<Vec<(String, IgnoredAny)>>::try_from_uri(request.uri()).ok()?;
    Some(
        parameters
            .iter()
            .any(|(name, _)| name == "token" || name == "access_token"),
    )
}

/// An Authorization header, a token query parameter or a query too malformed to rule one out.
fn carries_credential(request: &Request) -> bool {
    request
        .headers()
        .contains_key(axum::http::header::AUTHORIZATION)
        || query_credential(request) != Some(false)
}

/// Discovery and the password endpoints answer a request that carries no credential; everything else, and
/// any request that does carry one, is authenticated.
fn public_route(method: &Method, path: &str) -> bool {
    match path {
        "/api" => matches!(*method, Method::GET | Method::HEAD),
        "/api/v1/auth/setup" | "/api/v1/auth/login" => *method == Method::POST,
        _ => false,
    }
}

pub(super) async fn boundary(
    State(state): State<Arc<NativeState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = request.method().clone();
    let path = request.uri().path();
    let public = public_route(&method, path);
    let is_api = path == "/api" || path.starts_with("/api/");
    let is_ui = state.ui.is_some() && (matches!(path, "/" | "/ui") || path.starts_with("/ui/"));
    let route = request.extensions().get::<MatchedPath>().cloned();
    let template = route.as_ref().map_or("unmatched", MatchedPath::as_str);
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    let mut origin = None;
    let mut lease = None;
    let result: Result<Response, ApiError> = async {
        let header_bytes = check_bounds(&request, &request_id)?;
        origin = state
            .security
            .check_origin(request.headers(), &request_id)?;
        if is_api && method == Method::OPTIONS {
            return if route.is_some() {
                Ok(next.run(request).await)
            } else {
                preflight(&request, &[], &request_id)
            };
        }
        if is_api {
            // A public route still records whether the caller is admitted, so discovery can withhold detail.
            match state.security.authenticate(
                &request,
                state.auth.as_ref().map(|auth| &auth.sessions),
                &request_id,
            ) {
                Ok(session) => {
                    lease = session;
                    request.extensions_mut().insert(Admitted);
                }
                Err(error) if !public || carries_credential(&request) => return Err(error),
                Err(_) => {}
            }
            let (parts, body) = request.into_parts();
            let bytes = read_body(body, header_bytes, &request_id).await?;
            if matches!(method, Method::GET | Method::HEAD) && !bytes.is_empty() {
                return Err(invalid_request(
                    &request_id,
                    json!({"field":"body","kind":"not_allowed"}),
                ));
            }
            request = Request::from_parts(parts, Body::from(bytes.freeze()));
        }
        Ok(next.run(request).await)
    }
    .await;
    let boundary_error = result.is_err();
    let mut response = match (result, lease) {
        (Ok(response), Some(lease)) if is_event_stream(&response) => {
            end_with_session(response, lease)
        }
        (Ok(response), _) => response,
        (Err(error), _) => error.into_response(),
    };
    if is_api || boundary_error {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    if is_ui && boundary_error {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    if is_api && response.status() == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response.headers_mut().insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("Location, Retry-After, ETag"),
        );
    }
    if method == Method::HEAD {
        if !response.headers().contains_key(header::CONTENT_LENGTH)
            && response.status() != StatusCode::NO_CONTENT
            && response.status() != StatusCode::NOT_MODIFIED
            && !response.status().is_informational()
            && let Some(length) = response.body().size_hint().exact()
        {
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        *response.body_mut() = Body::empty();
    }
    let logged_method = match method {
        Method::GET
        | Method::HEAD
        | Method::POST
        | Method::PUT
        | Method::DELETE
        | Method::CONNECT
        | Method::OPTIONS
        | Method::TRACE
        | Method::PATCH => method.as_str(),
        _ => "OTHER",
    };
    // A dashboard polls every few seconds; only rejected or failed requests earn an INFO line,
    // and a refused configuration write a WARN line naming why.
    let status = response.status().as_u16();
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    log_request(
        logged_method,
        template,
        status,
        elapsed_ms,
        &request_id,
        response.extensions().get::<WriteRefusal>().copied(),
    );
    response
}

pub(super) fn log_request(
    method: &str,
    template: &str,
    status: u16,
    elapsed_ms: f64,
    request_id: &str,
    reason: Option<WriteRefusal>,
) {
    if let Some(reason) = reason {
        tracing::warn!(
            method,
            route = template,
            status,
            elapsed_ms,
            request_id = %request_id,
            reason = reason.as_str(),
            message = "native HTTP request"
        );
    } else if status >= 400 {
        tracing::info!(
            method,
            route = template,
            status,
            elapsed_ms,
            request_id = %request_id,
            "native HTTP request"
        );
    } else {
        tracing::debug!(
            method,
            route = template,
            status,
            elapsed_ms,
            request_id = %request_id,
            "native HTTP request"
        );
    }
}

fn is_event_stream(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"))
}

/// Authorization is checked once per request, so a stream must end itself when its session does.
fn end_with_session(response: Response, lease: SessionLease) -> Response {
    let (parts, body) = response.into_parts();
    let stream = body.into_data_stream().take_until(Box::pin(lease.ended()));
    Response::from_parts(parts, Body::from_stream(stream))
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a HeaderValue>, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        Err(())
    } else {
        Ok(value)
    }
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers.iter().fold(0usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
    })
}

// Hyper normalizes targets and headers before this boundary (including fragment
// removal and equal Content-Length coalescing); these are application-view limits.
fn check_bounds(request: &Request, request_id: &str) -> Result<usize, ApiError> {
    let uri = request.uri();
    let target_bytes = uri.path_and_query().map_or(0, |value| value.as_str().len())
        + uri.scheme_str().map_or(0, |value| value.len() + 3)
        + uri.authority().map_or(0, |value| value.as_str().len());
    let header_bytes = header_bytes(request.headers());
    if target_bytes > MAX_TARGET_BYTES || header_bytes > MAX_HEADER_BYTES {
        return Err(too_large(request_id));
    }
    if let Some(length) = single_header(request.headers(), "content-length").map_err(|()| {
        invalid_request(
            request_id,
            json!({"header":"content-length","kind":"duplicate"}),
        )
    })? {
        let not_decimal = || {
            invalid_request(
                request_id,
                json!({"header":"content-length","kind":"not_decimal"}),
            )
        };
        let length = length.to_str().map_err(|_| not_decimal())?;
        if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(not_decimal());
        }
        if length
            .parse::<u64>()
            .map_or(true, |length| length > MAX_BODY_BYTES as u64)
        {
            return Err(too_large(request_id).with_details(super::body::too_large()));
        }
    }
    if uri.scheme().is_some() || uri.authority().is_some() || !uri.path().starts_with('/') {
        return Err(invalid_request(
            request_id,
            json!({"field":"target","kind":"not_origin_form"}),
        ));
    }
    Ok(header_bytes)
}

async fn read_body(
    mut body: Body,
    mut headers_size: usize,
    request_id: &str,
) -> Result<BytesMut, ApiError> {
    let mut bytes = BytesMut::new();
    while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame
            .map_err(|_| invalid_request(request_id, json!({"field":"body","kind":"malformed"})))?;
        match frame.into_data() {
            Ok(data) => {
                if data.len() > MAX_BODY_BYTES - bytes.len() {
                    return Err(too_large(request_id).with_details(super::body::too_large()));
                }
                bytes.extend_from_slice(&data);
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    headers_size = headers_size.saturating_add(header_bytes(&trailers));
                    if headers_size > MAX_HEADER_BYTES {
                        return Err(too_large(request_id));
                    }
                }
            }
        }
    }
    Ok(bytes)
}

pub(super) fn preflight(
    request: &Request,
    methods: &[&str],
    request_id: &str,
) -> Result<Response, ApiError> {
    if !request.headers().contains_key(header::ORIGIN) {
        return Err(invalid_request(
            request_id,
            json!({"header":"origin","kind":"missing"}),
        ));
    }
    let method_error = |kind| {
        invalid_request(
            request_id,
            json!({"header":"access-control-request-method","kind":kind}),
        )
    };
    let method = single_header(request.headers(), "access-control-request-method")
        .map_err(|()| method_error("duplicate"))?
        .ok_or_else(|| method_error("missing"))?
        .to_str()
        .map_err(|_| method_error("not_text"))?;
    if !methods.contains(&method) && !(method == "HEAD" && methods.contains(&"GET")) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::ResourceNotFound,
            "The requested resource was not found.",
            Some(request_id.to_owned()),
        ));
    }
    for value in request
        .headers()
        .get_all(header::ACCESS_CONTROL_REQUEST_HEADERS)
    {
        let value = value.to_str().map_err(|_| {
            invalid_request(
                request_id,
                json!({"header":"access-control-request-headers","kind":"not_text"}),
            )
        })?;
        for name in value.split(',').map(|name| name.trim_matches([' ', '\t'])) {
            if name.is_empty() {
                return Err(invalid_request(
                    request_id,
                    json!({"header":"access-control-request-headers","kind":"empty_name"}),
                ));
            }
            if !ALLOW_HEADERS
                .split(", ")
                .any(|allowed| allowed.eq_ignore_ascii_case(name))
            {
                return Err(forbidden(request_id));
            }
        }
    }
    let mut allowed_methods = methods.join(", ");
    if methods.contains(&"GET") {
        allowed_methods.push_str(", HEAD");
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_str(&allowed_methods).expect("native route methods are HTTP tokens"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOW_HEADERS),
    );
    response.headers_mut().append(
        header::VARY,
        HeaderValue::from_static("Access-Control-Request-Method, Access-Control-Request-Headers"),
    );
    Ok(response)
}

/// Details name the header or request part and the failed check; header and
/// body values are never echoed.
fn invalid_request(request_id: &str, details: Value) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "The request is invalid.",
        Some(request_id.to_owned()),
    )
    .with_details(details)
}

fn unauthorized(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        ErrorCode::AuthenticationRequired,
        "Valid bearer credentials are required.",
        Some(request_id.to_owned()),
    )
}

fn forbidden(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::PermissionDenied,
        "The request is not permitted by the HTTP security policy.",
        Some(request_id.to_owned()),
    )
}

fn too_large(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::RequestTooLarge,
        "The request exceeds an HTTP size limit.",
        Some(request_id.to_owned()),
    )
}
