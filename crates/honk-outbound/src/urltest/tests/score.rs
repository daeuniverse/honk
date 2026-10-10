use super::*;
use crate::group::{ScoreSelectionContext, ScoreSource, ScoreTarget, SelectionNetwork};
use honk_config::group::{Group, GroupPolicy};

#[tokio::test]
async fn head_fallback_does_not_certify_the_configured_get_latency() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_request_head(&mut stream).await;
            assert!(first.starts_with(b"HEAD "));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let second = read_request_head(&mut stream).await;
            assert!(second.starts_with(b"GET "));
        }
    });
    let nodes = [make_node("stable"), make_node("fallback")];
    let manager = GroupManager::new(
        &[Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }],
        &nodes,
    );
    let url = format!("http://{addr}/configured");
    let request = health_http_probe_request(&url, "GET").unwrap();
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(IpVersion::V4),
        health_family: IpVersion::V4,
        target: Some(ScoreTarget::Socket(addr)),
    };
    for (node, latency) in nodes.iter().zip([100, 200]) {
        for _ in 0..4 {
            let reporter = manager
                .feedback_for_node(node.id, context.clone())
                .unwrap()
                .with_source(ScoreSource::HealthProbe)
                .with_probe_identity(&request.uri().to_string(), "GET")
                .start();
            reporter.probe_latency(Duration::from_millis(latency));
            reporter.finish_setup_only();
        }
    }
    let mut guard = crate::runtime::NodeRuntime::try_ephemeral_guarded(&nodes[1]).unwrap();
    for _ in 0..4 {
        let feedback = manager
            .feedback_for_node(nodes[1].id, context.clone())
            .unwrap()
            .with_source(ScoreSource::HealthProbe);
        measure_http_probe(
            &guard.runtime(),
            &MockHandler,
            &request,
            addr,
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Some(feedback),
        )
        .await
        .expect("URLTest must preserve its valid HEAD fallback");
    }
    peer.await.unwrap();
    guard.close().await.unwrap();
    assert_eq!(
        manager.get_score_selection_for_network("score", SelectionNetwork::Tcp),
        Some("stable".into()),
        "a failed GET must not replace its 200ms evidence with a fast HEAD sample",
    );
}
