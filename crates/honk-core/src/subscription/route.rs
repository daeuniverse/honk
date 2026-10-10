//! How a subscription download leaves: straight to its host when its
//! `download_detour` is `direct`, otherwise through the routing rules or the
//! group it names, like every other download honk makes itself.

use honk_config::subscription::Subscription;
use tokio::time::Instant;

use crate::download_route::{Detour, Failed, NoUsableNode, Request};
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
    /// because its host usually differs.
    Routed(&'a Routing),
}

impl Hop<'_> {
    /// One GET of `url` that reads only the body of an answer that is
    /// neither followed nor failed.
    pub(super) async fn get(
        &self,
        subscription: &Subscription,
        url: &reqwest::Url,
        headers: &http::HeaderMap,
        deadline: Instant,
    ) -> anyhow::Result<Reply> {
        let max_bytes = super::MAX_SUBSCRIPTION_BYTES;
        let reply = match self {
            Self::Direct(client) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout_at(deadline, client.get(url, headers, remaining)).await {
                    Err(_) => Err("download_timeout"),
                    Ok(response) => {
                        marked_http::read(response?, wants_body, deadline.into(), max_bytes)
                            .await
                            .map_err(|error| error.stage)
                    }
                }
            }
            Self::Routed(routing) => {
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
                    )
                    .await;
                match fetched {
                    Ok((reply, _)) => Ok(reply),
                    Err(Failed::Stage(stage)) => Err(stage),
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
        reply.map_err(|stage| match stage {
            "asset_too_large" => anyhow::anyhow!("subscription body exceeds {max_bytes} bytes"),
            "route_blocked" => {
                anyhow::anyhow!("routing sends the subscription download to 'block'")
            }
            stage => anyhow::anyhow!("subscription download failed: {stage}"),
        })
    }
}

/// The body of every answer that is neither followed nor failed.
fn wants_body(status: http::StatusCode, headers: &http::HeaderMap) -> bool {
    !status.is_client_error()
        && !status.is_server_error()
        && !(marked_http::followed_redirect(status) && headers.contains_key(http::header::LOCATION))
}

#[cfg(test)]
mod tests;
