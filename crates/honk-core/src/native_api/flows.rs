//! HTTP projection of `crate::observe::flows`.

use axum::{
    Json,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};

use super::{
    NativeState, error, full_detail, invalid_query, parse_query,
    types::{ApiError, ErrorCode, RequestId},
};
use crate::observe::flows::{Filters, FlowMissing, PageRefusal};

pub(super) fn list(state: &NativeState, uri: &Uri, id: &RequestId) -> Result<Response, ApiError> {
    let query = parse_query(
        uri,
        &[
            "network",
            "state",
            "connection_id",
            "limit",
            "cursor",
            "detail",
        ],
        id,
    )?;
    let network = query.get("network").map(String::as_str).unwrap_or("all");
    let state_filter = query.get("state").map(String::as_str).unwrap_or("all");
    let limit = super::pages::limit(&query, id)?;
    if !matches!(network, "tcp" | "udp" | "all")
        || !(state_filter == "all"
            || crate::observe::vocab::ConnectionState::ALL
                .iter()
                .any(|state| state.as_str() == state_filter))
        || query
            .get("connection_id")
            .is_some_and(|value| value.is_empty())
        || query.get("cursor").is_some_and(|value| value.is_empty())
    {
        return Err(invalid_query(id));
    }
    let filters = Filters::new(
        network.to_owned(),
        state_filter.to_owned(),
        query.get("connection_id").cloned(),
        full_detail(&query, id)?,
        limit,
    );
    match state
        .observation
        .core
        .flows
        .page(filters, query.get("cursor").map(String::as_str))
    {
        Ok(page) => {
            Ok(Json(super::config::administrative_projection(state, page)?).into_response())
        }
        Err(refusal) => Ok(page_error(refusal, id).into_response()),
    }
}

pub(super) fn detail(
    state: &NativeState,
    flow_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let flow = state
        .observation
        .core
        .flows
        .get(flow_id)
        .map_err(|missing| missing_error(missing, id))?;
    Ok(Json(super::config::administrative_projection(state, flow)?).into_response())
}

fn page_error(refusal: PageRefusal, id: &RequestId) -> ApiError {
    match refusal {
        PageRefusal::Expired => error(
            StatusCode::GONE,
            ErrorCode::SnapshotExpired,
            "Flow snapshot expired",
            id,
        ),
        PageRefusal::Mismatch => invalid_query(id),
        PageRefusal::Busy => error(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::SnapshotUnavailable,
            "Flow snapshot capacity is full",
            id,
        ),
    }
}

fn missing_error(missing: FlowMissing, id: &RequestId) -> ApiError {
    match missing {
        FlowMissing::Expired => error(
            StatusCode::GONE,
            ErrorCode::FlowExpired,
            "Flow retention expired",
            id,
        ),
        FlowMissing::NotFound => error(
            StatusCode::NOT_FOUND,
            ErrorCode::ResourceNotFound,
            "Flow not found",
            id,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_error(error: ApiError, status: StatusCode, code: &str) {
        assert_eq!(serde_json::to_value(&error).unwrap()["error"]["code"], code);
        assert_eq!(error.into_response().status(), status);
    }

    #[test]
    fn refusals_keep_their_http_codes() {
        let id = RequestId("flow-test".to_owned());
        assert_error(
            page_error(PageRefusal::Expired, &id),
            StatusCode::GONE,
            "snapshot_expired",
        );
        assert_error(
            page_error(PageRefusal::Busy, &id),
            StatusCode::SERVICE_UNAVAILABLE,
            "snapshot_unavailable",
        );
        assert_error(
            page_error(PageRefusal::Mismatch, &id),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
        assert_error(
            missing_error(FlowMissing::Expired, &id),
            StatusCode::GONE,
            "flow_expired",
        );
        assert_error(
            missing_error(FlowMissing::NotFound, &id),
            StatusCode::NOT_FOUND,
            "resource_not_found",
        );
    }
}
