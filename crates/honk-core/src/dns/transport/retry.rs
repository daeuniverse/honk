use std::future::Future;

fn should_retry(error: &anyhow::Error) -> bool {
    !honk_outbound::proxy::is_packet_rejection(error)
        && !error.chain().any(|cause| {
            cause.is::<super::doh_message::DeterministicResponse>()
                || cause.is::<super::body::DnsMessageTooLarge>()
        })
}

pub(super) async fn exchange_with_retry<Once, Fut, Reset, ResetFut>(
    label: &'static str,
    raw_query: &[u8],
    once: Once,
    reset: Reset,
    feedback: Option<honk_outbound::group::ScoreBusinessGuard>,
) -> anyhow::Result<Vec<u8>>
where
    Once: Fn(Option<honk_outbound::group::ScoreReporter>) -> Fut,
    Fut: Future<Output = anyhow::Result<Vec<u8>>>,
    Reset: FnOnce(&anyhow::Error) -> ResetFut,
    ResetFut: Future<Output = ()>,
{
    let reporter = feedback.map(honk_outbound::group::ScoreBusinessGuard::start);
    let first_result = {
        let exchange = once(reporter.clone());
        crate::observe::scope_pin!(exchange);
        let exchange = crate::observe::flows::dns::transport_exchange_scope(raw_query, exchange);
        exchange.await
    };
    let result = match first_result {
        Ok(response) => Ok(response),
        Err(first) if !should_retry(&first) => Err(first),
        Err(first) => {
            record_reset(label);
            reset(&first).await;
            let exchange = once(reporter.clone());
            crate::observe::scope_pin!(exchange);
            let exchange =
                crate::observe::flows::dns::transport_exchange_scope(raw_query, exchange);
            exchange.await.map_err(|error| {
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
    use std::cell::Cell;
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
            |_| async {
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
    async fn dns_retry_settles_score_trial_once() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());

        for exhausted in [false, true] {
            let nodes = [
                Node::from_share_link("socks5://127.0.0.1:1080#seed").unwrap(),
                Node::from_share_link("socks5://127.0.0.1:1081#challenger").unwrap(),
            ];
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
                    "192.0.2.53:443".parse::<std::net::SocketAddr>().unwrap(),
                )),
            };

            // The cold challenger can receive a trial once the ordinary leaf completes a flow.
            let seed = manager
                .feedback_for_node(
                    nodes[0].id,
                    ScoreSelectionContext::aggregate(
                        context.network,
                        context.probe_domain,
                        context.health_family,
                    ),
                )
                .expect("seed feedback")
                .start();
            seed.setup_succeeded();
            seed.tx(1);
            seed.rx(1);
            seed.finish(ScoreOutcome::Success);

            let plan = manager.selection_plan_for_target("score", &context);
            let guard = plan.entries[0]
                .feedback
                .as_ref()
                .expect("planned Score trial")
                .begin()
                .expect("admitted Score trial");
            let outcomes = || {
                let c = manager.score_budget_counters("score", context.network);
                (c.trial_success, c.trial_failure, c.trial_cancelled)
            };
            let calls = Cell::new(0);
            let result = super::exchange_with_retry(
                "test",
                &query,
                |reporter| async {
                    let reporter = reporter.expect("Score reporter");
                    reporter.setup_succeeded();
                    let first_attempt = calls.replace(calls.get() + 1) == 0;
                    if first_attempt || exhausted {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "stale session",
                        )
                        .into());
                    }
                    reporter.tx(query.len() as u64);
                    reporter.first_response();
                    reporter.rx(response.len() as u64);
                    Ok(response.clone())
                },
                |_| async {
                    assert_eq!(outcomes(), (0, 0, 0), "the first reset settled the trial");
                },
                Some(guard),
            )
            .await;

            assert_eq!(calls.get(), 2);
            if exhausted {
                let error = result.expect_err("retry also resets");
                assert_eq!(
                    error.downcast_ref::<io::Error>().expect("I/O error").kind(),
                    io::ErrorKind::ConnectionReset,
                );
            } else {
                assert_eq!(result.expect("retry succeeds"), response);
            }
            assert_eq!(
                outcomes(),
                (u64::from(!exhausted), u64::from(exhausted), 0),
                "retry exhausted: {exhausted}",
            );
        }
    }

    #[tokio::test]
    async fn deterministic_answer_does_not_reset_or_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resets = Arc::new(AtomicUsize::new(0));
        let call_count = Arc::clone(&calls);
        let reset_count = Arc::clone(&resets);

        let error = super::exchange_with_retry(
            "test",
            &[0; 12],
            move |_| {
                call_count.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<Vec<u8>, _>(
                        crate::dns::transport::doh_message::DeterministicResponse {
                            transport: "DoH",
                            reason: "HTTP status 400".into(),
                        }
                        .into(),
                    )
                }
            },
            move |_| {
                reset_count.fetch_add(1, Ordering::SeqCst);
                async {}
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(
            error
                .chain()
                .any(|cause| cause.is::<super::super::doh_message::DeterministicResponse>())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resets.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn packet_rejection_does_not_reset_or_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resets = Arc::new(AtomicUsize::new(0));
        let call_count = Arc::clone(&calls);
        let reset_count = Arc::clone(&resets);

        let error = super::exchange_with_retry(
            "test",
            &[0; 12],
            move |_| {
                call_count.fetch_add(1, Ordering::SeqCst);
                async { Err::<Vec<u8>, _>(honk_outbound::proxy::PacketRejection::Policy.into()) }
            },
            move |_| {
                reset_count.fetch_add(1, Ordering::SeqCst);
                async {}
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(honk_outbound::proxy::is_packet_rejection(&error));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resets.load(Ordering::SeqCst), 0);
    }
}
