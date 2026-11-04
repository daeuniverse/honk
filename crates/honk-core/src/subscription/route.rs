//! How a subscription download leaves: straight to its host when its
//! `download_detour` is `direct`, otherwise through the routing rules or the
//! group it names, like every other download honk makes itself.

use honk_config::subscription::Subscription;
use honk_outbound::group::ScoreContinuation;
use tokio::time::Instant;

use crate::download_route::{Detour, Failed, NoUsableNode, Request, Via};
use crate::marked_http::{self, Reply};

pub(crate) type Routing = crate::download_route::SharedOutbounds;

/// The subscription is fetched straight from its host, outside routing.
pub(crate) fn direct(subscription: &Subscription) -> bool {
    matches!(Detour::parse(&subscription.download_detour), Detour::Direct)
}

/// The route chosen for a subscription has no node that can carry it, as when
/// the rules send it to a group of the nodes it has not delivered yet.
#[derive(Debug, thiserror::Error)]
#[error(
    "subscription '{subscription}': its download route '{outbound}' has no usable node yet, so it cannot carry this download; set route: direct for this subscription to fetch it outside routing"
)]
pub(crate) struct RouteUnavailable {
    subscription: String,
    outbound: String,
}

/// The download failed at `stage`, through `via` when a node carried it. The
/// message names the outbound, so the log shows which node to look at.
#[derive(Debug)]
pub(crate) struct DownloadFailed {
    subscription: String,
    stage: &'static str,
    via: Option<Via>,
    /// The rejecting answer, for the stages that come from a status.
    status: Option<http::StatusCode>,
}

impl DownloadFailed {
    /// The server answered with a client or server error, as an expired
    /// subscription token does. Geodata stages the same statuses alike.
    pub(crate) fn status(
        subscription: &Subscription,
        status: http::StatusCode,
        via: Option<Via>,
    ) -> Self {
        Self {
            subscription: subscription.name.clone(),
            stage: match status {
                http::StatusCode::NOT_FOUND => "http_not_found",
                _ => "http_status_rejected",
            },
            via,
            status: Some(status),
        }
    }
}

impl std::fmt::Display for DownloadFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            subscription,
            stage,
            via,
            status,
        } = self;
        if let Some(status) = status {
            return write!(f, "subscription server answered HTTP {status}");
        }
        match (*stage, via) {
            ("asset_too_large", _) => write!(
                f,
                "subscription body exceeds {} bytes",
                super::MAX_SUBSCRIPTION_BYTES
            ),
            ("route_blocked", _) => {
                f.write_str("routing sends the subscription download to 'block'")
            }
            (_, None) => write!(f, "subscription '{subscription}': download failed: {stage}"),
            (_, Some(Via { node, group })) => {
                write!(
                    f,
                    "subscription '{subscription}': download through node '{node}'"
                )?;
                if let Some(group) = group {
                    write!(f, " of group '{group}'")?;
                }
                write!(
                    f,
                    " failed: {stage}; set route: direct for this subscription to fetch it outside routing"
                )
            }
        }
    }
}

impl std::error::Error for DownloadFailed {}

/// Where and why a fetch failed, for the provider status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FetchFailure {
    pub(crate) stage: &'static str,
    pub(crate) via: Option<Via>,
}

/// The stage a failed fetch stopped at: a download stage, or `parse_failed`
/// when the body arrived but is not a usable subscription. Content errors are
/// the only `DetailedConfigError`s a fetch returns. `None` for failures that
/// name no stage, such as an invalid URL.
pub(crate) fn failure_stage(error: &anyhow::Error) -> Option<FetchFailure> {
    if let Some(failed) = error.downcast_ref::<DownloadFailed>() {
        return Some(FetchFailure {
            stage: failed.stage,
            via: failed.via.clone(),
        });
    }
    error
        .downcast_ref::<honk_config::error::DetailedConfigError>()
        .map(|_| FetchFailure {
            stage: "parse_failed",
            via: None,
        })
}

/// The provider status code for a failed fetch.
pub(crate) fn failure_code(error: &anyhow::Error) -> &'static str {
    if error.downcast_ref::<RouteUnavailable>().is_some() {
        "route_unavailable"
    } else {
        "fetch_failed"
    }
}

/// A hop's answer and the node that carried it, or the stage it failed at and the node.
type Attempt = Result<(Reply, Option<Via>), (&'static str, Option<Via>)>;

/// Where each request of a subscription fetch goes.
pub(super) enum Hop<'a> {
    /// Straight to the host on the marked client, outside routing.
    Direct(&'a marked_http::Client),
    /// Through the subscription's route, decided again for every redirect
    /// because its host usually differs. `original` is the chain's first
    /// admitted Score business, which later hops continue.
    Routed {
        routing: &'a Routing,
        original: Option<ScoreContinuation>,
    },
}

impl Hop<'_> {
    /// One GET of `url` that reads only the body of an answer that is
    /// neither followed nor failed.
    pub(super) async fn get(
        &mut self,
        subscription: &Subscription,
        url: &reqwest::Url,
        headers: &http::HeaderMap,
        deadline: Instant,
    ) -> anyhow::Result<(Reply, Option<Via>)> {
        let max_bytes = super::MAX_SUBSCRIPTION_BYTES;
        let reply: Attempt = match self {
            Self::Direct(client) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout_at(deadline, client.get(url, headers, remaining)).await {
                    Err(_) => Err(("download_timeout", None)),
                    Ok(response) => match response {
                        Ok(response) => {
                            marked_http::read(response, wants_body, deadline.into(), max_bytes)
                                .await
                                .map(|reply| (reply, None))
                                .map_err(|error| (error.stage, None))
                        }
                        // A failure that fits no stage, such as an invalid URL,
                        // keeps its own message.
                        Err(error) => match direct_stage(&error) {
                            Some(stage) => Err((stage, None)),
                            None => return Err(error),
                        },
                    },
                }
            }
            Self::Routed { routing, original } => {
                let request = Request {
                    url,
                    headers,
                    wants_body,
                    deadline: deadline.into(),
                    max_bytes,
                    bootstrap: None,
                };
                let fetched = routing
                    .outbounds()
                    .fetch(
                        Detour::parse(&subscription.download_detour),
                        "subscription.download_detour",
                        "subscription download",
                        &request,
                        original,
                    )
                    .await;
                match fetched {
                    Ok((reply, _, via)) => Ok((reply, via)),
                    Err(Failed::Stage(stage, via)) => Err((stage, via)),
                    Err(Failed::Route(error)) => {
                        return Err(match error.downcast_ref::<NoUsableNode>() {
                            Some(unusable) => anyhow::Error::new(RouteUnavailable {
                                subscription: subscription.name.clone(),
                                outbound: unusable.outbound.clone(),
                            }),
                            None => error,
                        });
                    }
                }
            }
        };
        reply.map_err(|(stage, via)| {
            anyhow::Error::new(DownloadFailed {
                subscription: subscription.name.clone(),
                stage,
                via,
                status: None,
            })
        })
    }
}

/// The stage of an error the direct client returns without one, from what it
/// wraps: a timed-out socket, a TLS failure inside the handshake's io error, a
/// lookup that found no address, or else any other connect error. Nothing
/// else (an invalid URL, an unsupported scheme) names a stage.
fn direct_stage(error: &anyhow::Error) -> Option<&'static str> {
    if let Some(failed) = error.downcast_ref::<marked_http::Error>() {
        return Some(failed.stage);
    }
    let io = error.downcast_ref::<std::io::Error>()?;
    if io
        .get_ref()
        .is_some_and(|inner| inner.is::<tokio_rustls::rustls::Error>())
    {
        return Some("tls_failed");
    }
    Some(match io.kind() {
        std::io::ErrorKind::TimedOut => "download_timeout",
        std::io::ErrorKind::NotFound => "resolution_failed",
        std::io::ErrorKind::InvalidInput => return None,
        _ => "connection_failed",
    })
}

/// The body of every answer that is neither followed nor failed.
fn wants_body(status: http::StatusCode, headers: &http::HeaderMap) -> bool {
    !status.is_client_error()
        && !status.is_server_error()
        && !(marked_http::followed_redirect(status) && headers.contains_key(http::header::LOCATION))
}

#[cfg(test)]
mod tests;
