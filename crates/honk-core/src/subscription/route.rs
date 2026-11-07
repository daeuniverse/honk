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

/// Classified download failure with selected-outbound metadata when available.
#[derive(Debug)]
pub(crate) struct DownloadFailed {
    subscription: String,
    stage: &'static str,
    via: Option<Via>,
    status: Option<http::StatusCode>,
    /// The io error behind a direct failure. Only its own text is kept: the
    /// error types around a request name its URL, which carries the token.
    cause: Option<String>,
}

impl DownloadFailed {
    fn new(subscription: &Subscription, stage: &'static str, via: Option<Via>) -> Self {
        Self {
            subscription: subscription.name.clone(),
            stage,
            via,
            status: None,
            cause: None,
        }
    }

    /// The server answered with a client or server error, as an expired
    /// subscription token does. Geodata stages the same statuses alike.
    pub(crate) fn status(
        subscription: &Subscription,
        status: http::StatusCode,
        via: Option<Via>,
    ) -> Self {
        Self {
            status: Some(status),
            ..Self::new(
                subscription,
                crate::download_route::status_stage(status),
                via,
            )
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
            cause,
        } = self;
        match *stage {
            "asset_too_large" => {
                return write!(
                    f,
                    "subscription body exceeds {} bytes",
                    super::MAX_SUBSCRIPTION_BYTES
                );
            }
            "route_blocked" => {
                return f.write_str("routing sends the subscription download to 'block'");
            }
            _ => {}
        }
        write!(f, "subscription '{subscription}': ")?;
        match (status, via) {
            (Some(status), None) => write!(f, "server answered HTTP {status}"),
            (None, None) => {
                write!(f, "download failed: {stage}")?;
                match cause {
                    Some(cause) => write!(f, " ({cause})"),
                    None => Ok(()),
                }
            }
            (status, Some(via)) => {
                match status {
                    Some(status) => write!(f, "server answered HTTP {status} through {via}")?,
                    None => write!(f, "download through {via} failed: {stage}")?,
                }
                f.write_str("; set route: direct for this subscription to fetch it outside routing")
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
        let reply = match self {
            Self::Direct(client) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout_at(deadline, client.get(url, headers, remaining)).await {
                    Err(_) => Err(DownloadFailed::new(subscription, "download_timeout", None)),
                    Ok(response) => match response {
                        Ok(response) => {
                            marked_http::read(response, wants_body, deadline.into(), max_bytes)
                                .await
                                .map(|reply| (reply, None))
                                .map_err(|error| {
                                    DownloadFailed::new(subscription, error.stage, None)
                                })
                        }
                        Err(error) => match direct_stage(&error) {
                            Some((stage, cause)) => Err(DownloadFailed {
                                cause,
                                ..DownloadFailed::new(subscription, stage, None)
                            }),
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
                    Err(Failed::Stage(stage, via)) => {
                        Err(DownloadFailed::new(subscription, stage, via))
                    }
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
        reply.map_err(anyhow::Error::new)
    }
}

/// Classify direct-client errors without retaining URL-bearing request wrappers.
fn direct_stage(error: &anyhow::Error) -> Option<(&'static str, Option<String>)> {
    if let Some(failed) = error.downcast_ref::<marked_http::Error>() {
        return Some((failed.stage, None));
    }
    let io = error.downcast_ref::<std::io::Error>()?;
    let stage = if io
        .get_ref()
        .is_some_and(|inner| inner.is::<tokio_rustls::rustls::Error>())
    {
        "tls_failed"
    } else {
        match io.kind() {
            std::io::ErrorKind::TimedOut => "download_timeout",
            std::io::ErrorKind::NotFound => "resolution_failed",
            std::io::ErrorKind::InvalidInput => return None,
            _ => "connection_failed",
        }
    };
    Some((stage, Some(io.to_string())))
}

/// The body of every answer that is neither followed nor failed.
fn wants_body(status: http::StatusCode, headers: &http::HeaderMap) -> bool {
    !status.is_client_error()
        && !status.is_server_error()
        && !(marked_http::followed_redirect(status) && headers.contains_key(http::header::LOCATION))
}

#[cfg(test)]
mod tests;
