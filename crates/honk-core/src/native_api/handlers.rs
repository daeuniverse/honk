//! Native HTTP method registration and resource adapters.

use std::sync::Arc;

use axum::extract::{Extension, Request, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, get, post, put};
use axum::{Json, Router};

use super::{
    ApiError, ErrorCode, NativeState, catalog, config, connections, datapath, dns, error, events,
    flows, geodata, groups, logs, management, parse_query, probes, providers, routing, security,
    settings, telemetry, types,
};
use types::RequestId;

type App = State<Arc<NativeState>>;
type Id = Extension<RequestId>;

pub(super) fn routes() -> Router<Arc<NativeState>> {
    Router::new()
        .route("/api", resource(get(discovery), &["GET"]))
        .route(
            "/api/v1/auth/setup",
            resource(post(super::auth::setup), &["POST"]),
        )
        .route(
            "/api/v1/auth/login",
            resource(post(super::auth::login), &["POST"]),
        )
        .route(
            "/api/v1/auth/logout",
            resource(post(super::auth::logout), &["POST"]),
        )
        .route(
            "/api/v1/version",
            resource(
                get(|Extension(id): Id, uri: Uri| async move {
                    respond(
                        parse_query(&uri, &[], &id).map(|_| Json(types::version()).into_response()),
                        id,
                    )
                }),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/capabilities",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        if let Err(error) = parse_query(&uri, &[], &id) {
                            return error.into_response();
                        }
                        Json(types::capabilities(&state).await).into_response()
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/config",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(config::get(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/config/validate",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(config::validate(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/x-honk/config/export",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(config::export(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/x-honk/config/import",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(config::import(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/x-honk/config/revisions",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(config::revisions(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/x-honk/config/revisions/{number}/activate",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(config::activate(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/config/sources",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(config::create(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/config/sources/{source_id}",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(
                            config::source(&state, path_id(uri.path()), &uri, &id).await,
                            id,
                        )
                    },
                )
                .put(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let source_id = path_id(request.uri().path()).to_owned();
                        respond(config::replace(&state, source_id, request, &id).await, id)
                    },
                ),
                &["GET", "PUT"],
            ),
        )
        .route(
            "/api/v1/runtime",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(super::runtime(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/runtime/memory",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(telemetry::memory(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/runtime/outbounds",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(telemetry::outbounds(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/runtime/traffic/history",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(telemetry::traffic_history(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/runtime/memory/history",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(telemetry::memory_history(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/x-honk/runtime/mode",
            resource(get(unsupported).put(unsupported), &["GET", "PUT"]),
        )
        .route(
            "/api/v1/datapath",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(datapath::get(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/nodes",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(catalog::nodes(&state, &uri, &id).await, id)
                    },
                )
                .post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(
                            management::mutate(
                                &state,
                                management::Action::CreateNode,
                                request,
                                &id,
                            )
                            .await,
                            id,
                        )
                    },
                ),
                &["GET", "POST"],
            ),
        )
        .route(
            "/api/v1/nodes/{id}",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(
                            catalog::node(&state, path_id(uri.path()), &uri, &id).await,
                            id,
                        )
                    },
                )
                .delete(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let action = management::Action::Delete(management::Mutation::DeleteNode(
                            path_id(request.uri().path()).to_owned(),
                        ));
                        respond(management::mutate(&state, action, request, &id).await, id)
                    },
                ),
                &["GET", "DELETE"],
            ),
        )
        .route(
            "/api/v1/providers",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(providers::list(&state, &uri, &id).await, id)
                    },
                )
                .post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(
                            management::mutate(
                                &state,
                                management::Action::CreateProvider,
                                request,
                                &id,
                            )
                            .await,
                            id,
                        )
                    },
                ),
                &["GET", "POST"],
            ),
        )
        .route(
            "/api/v1/providers/{id}",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(
                            providers::detail(&state, path_id(uri.path()), &uri, &id).await,
                            id,
                        )
                    },
                )
                .delete(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let action =
                            management::Action::Delete(management::Mutation::DeleteProvider(
                                path_id(request.uri().path()).to_owned(),
                            ));
                        respond(management::mutate(&state, action, request, &id).await, id)
                    },
                ),
                &["GET", "DELETE"],
            ),
        )
        .route(
            "/api/v1/providers/{id}/refresh",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let provider_id =
                            path_id(request.uri().path().trim_end_matches("/refresh")).to_owned();
                        respond(
                            providers::refresh(&state, &provider_id, request, &id).await,
                            id,
                        )
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/geodata",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(geodata::get(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/geodata/update",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(geodata::update(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/groups",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(catalog::groups(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/groups/{groupId}",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(
                            catalog::group(&state, path_id(uri.path()), &uri, &id).await,
                            id,
                        )
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/groups/{groupId}/config",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        let group_id = config_group_id(uri.path());
                        respond(catalog::group_config(&state, group_id, &uri, &id).await, id)
                    },
                )
                .patch(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let group_id = config_group_id(request.uri().path()).to_owned();
                        respond(groups::patch(&state, &group_id, request, &id).await, id)
                    },
                ),
                &["GET", "PATCH"],
            ),
        )
        .route(
            "/api/v1/groups/{groupId}/selection",
            resource(
                put(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let group_id =
                            path_id(request.uri().path().trim_end_matches("/selection")).to_owned();
                        respond(groups::select(&state, &group_id, request, &id).await, id)
                    },
                )
                .delete(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let group_id =
                            path_id(request.uri().path().trim_end_matches("/selection")).to_owned();
                        respond(
                            groups::clear_override(&state, &group_id, request.uri(), &id).await,
                            id,
                        )
                    },
                ),
                &["PUT", "DELETE"],
            ),
        )
        .route(
            "/api/v1/probes",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(probes::create(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/connections",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(super::connections(&state, &uri, &id), id)
                    },
                )
                .delete(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(connections::close_bulk(&state, request, &id).await, id)
                    },
                ),
                &["GET", "DELETE"],
            ),
        )
        .route(
            "/api/v1/connections/{connection_id}",
            resource(
                delete(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let connection_id = path_id(request.uri().path()).to_owned();
                        respond(
                            connections::close(&state, &connection_id, request, &id).await,
                            id,
                        )
                    },
                ),
                &["DELETE"],
            ),
        )
        .route(
            "/api/v1/flows",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(flows::list(&state, &uri, &id), id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/flows/{flow_id}",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(flows::detail(&state, path_id(uri.path()), &uri, &id), id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/routing/trace",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(routing::trace(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/rules",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(routing::rules(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/events",
            resource(
                get(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(events::serve(&state, request, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/logs",
            resource(
                get(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(logs::serve(&state, request, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/runtime/settings",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(settings::get(&state, &uri, &id).await, id)
                    },
                )
                .patch(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(settings::patch(&state, request, &id).await, id)
                    },
                ),
                &["GET", "PATCH"],
            ),
        )
        .route(
            "/api/v1/dns/query",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(dns::query(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/dns/rules",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(dns::rules::serve(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/dns/log",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(dns::log(&state, &uri, &id).await, id)
                    },
                ),
                &["GET"],
            ),
        )
        .route(
            "/api/v1/dns/cache",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        respond(dns::cache(&state, &uri, &id).await, id)
                    },
                )
                .delete(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(dns::delete_name(&state, request, &id).await, id)
                    },
                ),
                &["GET", "DELETE"],
            ),
        )
        .route(
            "/api/v1/dns/cache/{entry_id}",
            resource(
                delete(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        let entry_id = path_id(request.uri().path()).to_owned();
                        respond(dns::delete_entry(&state, &entry_id, request, &id).await, id)
                    },
                ),
                &["DELETE"],
            ),
        )
        .route(
            "/api/v1/dns/cache/flush",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(dns::flush(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/operations/reload",
            resource(
                post(
                    |State(state): App, Extension(id): Id, request: Request| async move {
                        respond(config::reload(&state, request, &id).await, id)
                    },
                ),
                &["POST"],
            ),
        )
        .route(
            "/api/v1/operations/suspend",
            resource(post(unsupported), &["POST"]),
        )
        .route(
            "/api/v1/operations/resume",
            resource(post(unsupported), &["POST"]),
        )
        .route(
            "/api/v1/operations/{id}",
            resource(
                get(
                    |State(state): App, Extension(id): Id, uri: Uri| async move {
                        let result = parse_query(&uri, &[], &id)
                            .and_then(|_| state.observation.operations.get(path_id(uri.path())));
                        respond(result, id)
                    },
                ),
                &["GET"],
            ),
        )
}

fn resource(
    router: MethodRouter<Arc<NativeState>>,
    methods: &'static [&'static str],
) -> MethodRouter<Arc<NativeState>> {
    router
        .options(move |Extension(id): Id, request: Request| async move {
            security::preflight(&request, methods, &id.0)
                .unwrap_or_else(IntoResponse::into_response)
        })
        // Replaces axum's empty 405 with the native JSON error.
        .fallback(move |Extension(id): Id| async move {
            let mut response = error(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::MethodNotAllowed,
                "Method not allowed",
                &id,
            )
            .into_response();
            // `get()` also serves HEAD, so a GET resource must advertise it.
            let mut allow = methods.join(", ");
            if methods.contains(&"GET") {
                allow.push_str(", HEAD");
            }
            response.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_str(&allow).expect("static method names"),
            );
            response
        })
}

async fn discovery(
    State(state): App,
    Extension(id): Id,
    admitted: Option<Extension<types::Admitted>>,
    uri: Uri,
) -> Response {
    respond(
        parse_query(&uri, &[], &id).map(|_| {
            Json(types::discovery(state.auth_discovery(), admitted.is_some())).into_response()
        }),
        id,
    )
}

fn respond(result: Result<Response, ApiError>, id: RequestId) -> Response {
    result.unwrap_or_else(|error| error.with_request_id(id.0).into_response())
}

fn path_id(path: &str) -> &str {
    // IDs remain raw URI segments: percent-encoded bytes must not alias another resource.
    path.rsplit('/').next().expect("matched resource path")
}

/// The group segment of `/groups/{groupId}/config`, even for a group whose id is `config`.
fn config_group_id(path: &str) -> &str {
    path_id(
        path.strip_suffix("/config")
            .expect("matched group config path"),
    )
}

async fn unsupported(Extension(id): Id) -> Response {
    error(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Capability is not supported",
        &id,
    )
    .into_response()
}
