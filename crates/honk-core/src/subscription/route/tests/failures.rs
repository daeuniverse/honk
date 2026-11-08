use super::super::{FetchFailure, direct_stage, failure_code, failure_stage};
use super::*;
use crate::download_route::Via;
#[cfg(feature = "native-api")]
use crate::subscription::SubscriptionSupervisor;

/// A download that fails names the node and group it went through, so the log
/// and the provider status point at the outbound to fix.
#[tokio::test]
async fn a_failed_routed_download_names_the_node_and_group() {
    let (address, requests) = server().await;
    let (routing, dials) = routing_via("proxy", true);
    let error = manager(routing)
        .fetch(&subscription(address, ""))
        .await
        .unwrap_err();
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert_eq!(failure_code(&error), "fetch_failed", "{error:#}");
    let message = error.to_string();
    for field in [
        "'own-provider'",
        "'tunnel'",
        "'proxy'",
        "connection_failed",
        "route: direct",
    ] {
        assert!(message.contains(field), "{message}");
    }
    assert_eq!(
        failure_stage(&error),
        Some(FetchFailure {
            stage: "connection_failed",
            via: Some(Via {
                node: "tunnel".into(),
                group: Some("proxy".into()),
            }),
        })
    );
    assert!(requests.lock().is_empty(), "never fetched direct");
}

/// A download the rules send straight to its host has no node to name.
#[tokio::test]
async fn a_failed_direct_download_names_no_node() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (routing, dials) = routing("direct");
    let error = manager(routing)
        .fetch(&subscription(closed, ""))
        .await
        .unwrap_err();
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    assert_eq!(failure_code(&error), "fetch_failed", "{error:#}");
    let message = error.to_string();
    assert!(message.contains("'own-provider'"), "{message}");
    assert!(message.contains("connection_failed"), "{message}");
    for field in ["'tunnel'", "'proxy'", "route: direct"] {
        assert!(!message.contains(field), "{message}");
    }
    assert_eq!(
        failure_stage(&error),
        Some(FetchFailure {
            stage: "connection_failed",
            via: None,
        })
    );
}

/// A rejecting answer, such as an expired token, is staged by its status,
/// through a node or direct, and keeps the status in its message.
#[tokio::test]
async fn a_rejected_status_is_staged_with_the_node_it_went_through() {
    for (status, stage) in [
        ("403 Forbidden", "http_status_rejected"),
        ("404 Not Found", "http_not_found"),
        ("503 Service Unavailable", "http_status_rejected"),
    ] {
        let (address, _) = serve(move |_| {
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        })
        .await;
        for (detour, rules, via) in [
            (
                "",
                "proxy",
                Some(Via {
                    node: "tunnel".into(),
                    group: Some("proxy".into()),
                }),
            ),
            ("", "direct", None),
            ("direct", "proxy", None),
        ] {
            let (routing, _) = routing(rules);
            let error = manager(routing)
                .fetch(&subscription(address, detour))
                .await
                .unwrap_err();
            assert_eq!(failure_code(&error), "fetch_failed", "{error:#}");
            assert!(error.to_string().contains(&status[..3]), "{error}");
            assert_eq!(
                failure_stage(&error),
                Some(FetchFailure { stage, via }),
                "{status} via {detour:?} {rules}"
            );
        }
    }
}

#[tokio::test]
async fn a_direct_connection_refusal_is_staged_and_an_invalid_url_is_not() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (outbounds, dials) = routing("proxy");
    let mut refused = subscription(closed, "direct");
    refused.url =
        format!("http://user-sentinel:password-sentinel@{closed}/sub?token=query-sentinel");
    let error = manager(outbounds).fetch(&refused).await.unwrap_err();
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    for diagnostic in [error.to_string(), format!("{error:?}")]
        .into_iter()
        .chain(error.chain().map(ToString::to_string))
    {
        assert!(!diagnostic.contains(&closed.to_string()) && !diagnostic.contains("http"));
        for sentinel in ["user-sentinel", "password-sentinel", "query-sentinel"] {
            assert!(!diagnostic.contains(sentinel), "{diagnostic}");
        }
    }
    assert_eq!(
        failure_stage(&error),
        Some(FetchFailure {
            stage: "connection_failed",
            via: None,
        })
    );
    let (outbounds, _) = routing("proxy");
    let mut invalid = subscription(closed, "direct");
    invalid.url = "ftp://127.0.0.1/sub".into();
    let error = manager(outbounds).fetch(&invalid).await.unwrap_err();
    assert_eq!(failure_stage(&error), None, "{error:#}");
}

#[test]
fn direct_errors_map_to_the_stage_their_cause_names() {
    use std::io::{Error, ErrorKind};
    use tokio_rustls::rustls::{CertificateError, Error as TlsError};
    let stage = |error: Error| direct_stage(&anyhow::Error::new(error));
    let named = |stage: &'static str, cause: &str| Some((stage, Some(cause.to_owned())));
    assert_eq!(
        stage(Error::new(ErrorKind::TimedOut, "deadline elapsed")),
        named("download_timeout", "deadline elapsed")
    );
    assert_eq!(
        stage(Error::new(ErrorKind::NotFound, "no DNS addresses")),
        named("resolution_failed", "no DNS addresses")
    );
    assert_eq!(
        stage(Error::other(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer
        )))
        .map(|found| found.0),
        Some("tls_failed")
    );
    assert_eq!(
        stage(Error::new(ErrorKind::ConnectionReset, "reset")),
        named("connection_failed", "reset")
    );
    assert_eq!(stage(Error::from(ErrorKind::InvalidInput)), None);
    assert_eq!(direct_stage(&anyhow::anyhow!("bad URL")), None);
    assert_eq!(
        direct_stage(&anyhow::Error::new(crate::marked_http::Error::from(
            "http_failed"
        ))),
        Some(("http_failed", None))
    );
}

#[tokio::test]
async fn an_unusable_body_is_a_parse_failure_not_a_download_failure() {
    let (address, _) =
        serve(|_| "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\ninvalid body")
            .await;
    for detour in ["direct", ""] {
        let (routing, _) = routing("direct");
        let error = manager(routing)
            .fetch(&subscription(address, detour))
            .await
            .unwrap_err();
        assert_eq!(failure_code(&error), "fetch_failed", "{error:#}");
        assert_eq!(
            failure_stage(&error),
            Some(FetchFailure {
                stage: "parse_failed",
                via: None,
            }),
            "{error:#}"
        );
    }
}

/// A failure the supervisor observes carries the stage and node to the
/// provider status.
#[cfg(feature = "native-api")]
#[tokio::test]
async fn the_supervisor_records_where_a_fetch_failed() {
    let (address, _) = server().await;
    let mut config = Config {
        subscriptions: vec![subscription(address, "")],
        ..Default::default()
    };
    let sub = config.subscriptions[0].clone();
    let mut supervisor = SubscriptionSupervisor::prepare(&mut config, None, Vec::new())
        .await
        .unwrap();
    let (routing, _) = routing_via("proxy", true);
    supervisor.route_through(routing);
    let (merge_tx, _merges) = tokio::sync::mpsc::channel(4);
    supervisor.start(merge_tx);
    let handle = supervisor.handle();
    let load = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let load = handle.observation(&sub);
            if load.error.is_some() {
                return load;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(load.error, Some("fetch_failed"));
    assert_eq!(
        load.fetch,
        Some(FetchFailure {
            stage: "connection_failed",
            via: Some(Via {
                node: "tunnel".into(),
                group: Some("proxy".into()),
            }),
        })
    );
    supervisor.shutdown().await.unwrap();
}
