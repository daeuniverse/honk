use std::future::Future;

pub(super) async fn exchange_with_retry<Once, Fut, Reset, ResetFut>(
    label: &'static str,
    raw_query: &[u8],
    once: Once,
    reset: Reset,
    feedback: Option<&honk_outbound::group::ScoreFeedback>,
) -> anyhow::Result<Vec<u8>>
where
    Once: Fn(Option<honk_outbound::group::ScoreReporter>) -> Fut,
    Fut: Future<Output = anyhow::Result<Vec<u8>>>,
    Reset: FnOnce() -> ResetFut,
    ResetFut: Future<Output = ()>,
{
    let reporter = feedback.map(honk_outbound::group::ScoreFeedback::start);
    let result = match once(reporter.clone()).await {
        Ok(response) => Ok(response),
        Err(first) => {
            record_reset(label);
            reset().await;
            once(reporter.clone()).await.map_err(|error| {
                let detail = error.to_string();
                error.context(format!(
                    "{label} failed after retry: {detail} (first: {first})"
                ))
            })
        }
    };
    if let Some(reporter) = &reporter {
        match &result {
            Ok(response) if super::is_valid_response(raw_query, response) => {
                reporter.finish(honk_outbound::group::ScoreOutcome::Success)
            }
            Ok(_) => reporter.finish(honk_outbound::group::ScoreOutcome::Other),
            Err(error) => reporter.finish(honk_outbound::group::ScoreOutcome::from_error(error)),
        }
    }
    result
}

fn record_reset(label: &'static str) {
    crate::stats::record_dns_event(crate::stats::DnsStatEvent::TransportReset);
    tracing::debug!(
        transport = label,
        error_kind = "exchange_failed",
        "DNS transport reset before retry"
    );
}

#[cfg(test)]
mod tests {
    use honk_config::group::GroupPolicy;
    use honk_config::node::{Group, Node};
    use honk_outbound::alive::{IpVersion, ProbeDomain};
    use honk_outbound::group::{
        GroupManager, ScoreOutcome, ScoreSelectionContext, ScoreTarget, SelectionNetwork,
    };
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn failed_exchange_records_reset_before_successful_retry() {
        let before = crate::stats::dns_snapshot();
        let calls = AtomicUsize::new(0);
        let resets = AtomicUsize::new(0);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer({
                let captured = Arc::clone(&captured);
                move || Capture(Arc::clone(&captured))
            })
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let response = super::exchange_with_retry(
            "test",
            &[0; 12],
            |_| async {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    anyhow::bail!("secret endpoint value")
                }
                Ok(vec![1, 2, 3])
            },
            || async {
                resets.fetch_add(1, Ordering::SeqCst);
            },
            None,
        )
        .await
        .expect("retry succeeds");

        assert_eq!(response, vec![1, 2, 3]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resets.load(Ordering::SeqCst), 1);
        let log = String::from_utf8(captured.lock().expect("capture").clone()).expect("UTF-8 log");
        assert!(log.contains("error_kind=\"exchange_failed\""));
        assert!(log.contains("transport=\"test\""));
        assert!(!log.contains("secret endpoint value"));
        assert!(crate::stats::dns_snapshot().delta(before).transport_reset >= 1);
    }

    #[tokio::test]
    async fn successful_retry_does_not_penalize_score_candidate() {
        let nodes = ["a", "b"].map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..Default::default()
        });
        let group = Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let manager = GroupManager::new(&[group], &nodes);
        let context = ScoreSelectionContext {
            network: SelectionNetwork::Tcp,
            probe_domain: ProbeDomain::Tcp,
            target_family: Some(IpVersion::V4),
            health_family: IpVersion::V4,
            target: Some(ScoreTarget::from(
                "8.8.8.8:443".parse::<std::net::SocketAddr>().unwrap(),
            )),
        };

        for node in &nodes {
            let feedback = manager
                .feedback_for_node(node.id, context.clone())
                .expect("Score candidate feedback");
            for _ in 0..32 {
                let reporter = feedback.start();
                reporter.setup_succeeded();
                reporter.tx(1);
                reporter.first_response();
                reporter.rx(1);
                reporter.finish(ScoreOutcome::Success);
            }
        }

        let plan = manager.selection_plan_for_target("score", &context);
        let incumbent = plan.entries[0].node.id;
        let feedback = plan.entries[0]
            .feedback
            .clone()
            .expect("Score candidate feedback");
        let calls = AtomicUsize::new(0);
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());

        for _ in 0..32 {
            super::exchange_with_retry(
                "test",
                &query,
                |reporter| async {
                    let reporter = reporter.expect("Score reporter");
                    reporter.setup_succeeded();
                    if calls.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "stale session",
                        )
                        .into());
                    }
                    reporter.tx(1);
                    reporter.first_response();
                    reporter.rx(1);
                    Ok(response.clone())
                },
                || async {},
                Some(&feedback),
            )
            .await
            .expect("retry succeeds");
        }

        let selected = manager.selection_plan_for_target("score", &context).entries[0]
            .node
            .id;
        assert_eq!(selected, incumbent);
    }
}
