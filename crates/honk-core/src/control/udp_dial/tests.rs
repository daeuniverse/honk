use super::*;
use honk_config::node::Node;
use std::sync::atomic::{AtomicUsize, Ordering};

fn candidate(name: &str) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("{name}.example"),
        port: 9,
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

#[tokio::test(start_paused = true)]
async fn udp_preparation_deadline_drains_pending_candidate() {
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let acquired = Arc::new(tokio::sync::Notify::new());
    let errors = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<(), Node> = {
        let permits = Arc::clone(&permits);
        let acquired = Arc::clone(&acquired);
        Arc::new(move |_, _| {
            let permits = Arc::clone(&permits);
            let acquired = Arc::clone(&acquired);
            Box::pin(async move {
                let _permit = permits.acquire_owned().await.unwrap();
                acquired.notify_one();
                std::future::pending::<anyhow::Result<()>>().await
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = Arc::clone(&errors);
            Arc::new(move |_, _| {
                errors.fetch_add(1, Ordering::Relaxed);
            })
        },
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
    let task = tokio::spawn(prepare_udp_plan(
        SelectionPlanMode::Authoritative,
        vec![candidate("pending")],
        deadline,
        prepare,
        callbacks,
    ));

    acquired.notified().await;
    assert_eq!(
        permits.available_permits(),
        0,
        "preparation acquired its permit"
    );
    tokio::time::advance(Duration::from_millis(10)).await;
    let result = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("UDP preparation must enforce its own deadline")
        .expect("preparation task must not panic");
    assert!(result.unwrap().is_none());
    assert_eq!(permits.available_permits(), 1);
    assert_eq!(errors.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_preparation_deadline_prevents_future_stagger_start() {
    let starts = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<(), Node> = {
        let starts = Arc::clone(&starts);
        Arc::new(move |_, _| {
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(anyhow::anyhow!("scripted dial error")) })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = Arc::clone(&errors);
            Arc::new(move |_, _| {
                errors.fetch_add(1, Ordering::SeqCst);
            })
        },
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    let task = tokio::spawn(prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![candidate("first"), candidate("after-deadline")],
        deadline,
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(20)).await;
    assert!(task.await.unwrap().unwrap().is_none());
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(errors.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn udp_preparation_deadline_drains_three_pending_candidates() {
    let permits = Arc::new(tokio::sync::Semaphore::new(3));
    let starts = Arc::new(AtomicUsize::new(0));
    let cancellations = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<(), Node> = {
        let permits = Arc::clone(&permits);
        let starts = Arc::clone(&starts);
        Arc::new(move |_, _| {
            let permits = Arc::clone(&permits);
            let starts = Arc::clone(&starts);
            Box::pin(async move {
                let _permit = permits.acquire_owned().await.unwrap();
                starts.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<anyhow::Result<()>>().await
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: Arc::new(|_, _| panic!("cancellation is health-neutral")),
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: {
            let cancellations = Arc::clone(&cancellations);
            Arc::new(move || {
                cancellations.fetch_add(1, Ordering::SeqCst);
            })
        },
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    let task = tokio::spawn(prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![
            candidate("first"),
            candidate("second"),
            candidate("third"),
            candidate("never-started"),
        ],
        deadline,
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert_eq!(starts.load(Ordering::SeqCst), 3);
    assert_eq!(permits.available_permits(), 0);
    tokio::time::advance(Duration::from_millis(20)).await;

    assert!(
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("all pending preparations must stop at the deadline")
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert_eq!(starts.load(Ordering::SeqCst), 3);
    assert_eq!(permits.available_permits(), 3);
    assert_eq!(cancellations.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn udp_policy_preflight_does_not_prepare_or_report_failure() {
    let starts = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<(), Node> = {
        let starts = Arc::clone(&starts);
        Arc::new(move |_, _| {
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| false),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = Arc::clone(&errors);
            Arc::new(move |_, _| {
                errors.fetch_add(1, Ordering::SeqCst);
            })
        },
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };

    let error = prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![candidate("rejected"), candidate("fallback")],
        tokio::time::Instant::now() + Duration::from_secs(1),
        prepare,
        callbacks,
    )
    .await
    .unwrap_err();

    assert!(honk_outbound::proxy::is_packet_rejection(&error));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert_eq!(errors.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn completed_udp_policy_rejection_does_not_fail_over_or_report_failure() {
    let starts = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<(), Node> = {
        let starts = Arc::clone(&starts);
        Arc::new(move |index, _| {
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if index == 0 {
                    Err(honk_outbound::proxy::PacketRejection::Policy.into())
                } else {
                    Ok(())
                }
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|_| true),
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = Arc::clone(&errors);
            Arc::new(move |_, _| {
                errors.fetch_add(1, Ordering::SeqCst);
            })
        },
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };

    let error = prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![candidate("rejected"), candidate("fallback")],
        tokio::time::Instant::now() + Duration::from_secs(1),
        prepare,
        callbacks,
    )
    .await
    .unwrap_err();

    assert!(honk_outbound::proxy::is_packet_rejection(&error));
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(errors.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn unscheduled_policy_denial_does_not_veto_an_earlier_winner() {
    let prepare: UdpPrepare<(), Node> = Arc::new(|index, _| {
        assert_eq!(index, 0, "the later candidate must not start");
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok(())
        })
    });
    let callbacks = UdpStaggerCallbacks {
        allows_target: Arc::new(|node: &Node| node.name != "later-denied"),
        is_eligible: Arc::new(|_| true),
        on_dial_error: Arc::new(|_, _| panic!("no candidate failed")),
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };
    let winner = prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![candidate("allowed"), candidate("later-denied")],
        tokio::time::Instant::now() + Duration::from_secs(1),
        prepare,
        callbacks,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(winner.0.name, "allowed");
}

#[tokio::test(start_paused = true)]
async fn udp_disabled_capability_falls_back_but_explicit_policy_is_terminal() {
    use crate::control::tests::support::{UdpTestHandler, UdpTestMode};
    use honk_config::node::{OutboundConfig, Udp443Policy, VlessConfig, VlessMultiplex};
    use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry};

    for policy_rejected in [false, true] {
        let mut first = candidate("vless");
        first.outbound = OutboundConfig::Vless(VlessConfig {
            uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            network: (!policy_rejected).then(|| "tcp".into()),
            multiplex: VlessMultiplex::xray(8, -1, Udp443Policy::Reject),
            ..Default::default()
        });
        first.id = first.derive_id();
        let second = candidate("fallback");
        let dials = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(UdpTestHandler {
            mode: UdpTestMode::CountDialAndSend {
                dials: dials.clone(),
                sends: Arc::new(AtomicUsize::new(0)),
            },
        });
        let mut registry = ProxyRegistry::new();
        for node in [&first, &second] {
            registry.register(
                ProtocolEntry::new(node.protocol(), handler.clone()).with_packet(handler.clone()),
            );
        }
        let registry = Arc::new(registry);
        let generation = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&[
                first.clone(),
                second.clone(),
            ])
            .unwrap(),
        );
        let target = "127.0.0.1:443".parse().unwrap();
        let prepare: UdpPrepare<(), Node> = Arc::new(move |_, node| {
            let registry = registry.clone();
            let generation = generation.clone();
            Box::pin(async move {
                registry
                    .dial_udp_transport_speculative(
                        generation,
                        node.id,
                        target,
                        None,
                        Duration::from_secs(1),
                    )
                    .await?;
                Ok(())
            })
        });
        let errors = Arc::new(AtomicUsize::new(0));
        let callbacks = UdpStaggerCallbacks {
            allows_target: Arc::new(move |node: &Node| {
                honk_outbound::descriptor::udp_target_allowed(node, 443)
            }),
            is_eligible: Arc::new(|_| true),
            on_dial_error: {
                let errors = errors.clone();
                Arc::new(move |_, _| {
                    errors.fetch_add(1, Ordering::SeqCst);
                })
            },
            on_attempt: Arc::new(|| {}),
            on_winner: Arc::new(|| {}),
            on_cancellation: Arc::new(|| {}),
        };
        let result = prepare_udp_plan(
            SelectionPlanMode::ColdUrlTest,
            vec![first, second],
            tokio::time::Instant::now() + Duration::from_secs(1),
            prepare,
            callbacks,
        )
        .await;
        if policy_rejected {
            assert!(honk_outbound::proxy::is_packet_rejection(
                &result.unwrap_err()
            ));
            assert_eq!(errors.load(Ordering::SeqCst), 0);
            assert_eq!(dials.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(result.unwrap().unwrap().0.name, "fallback");
            assert_eq!(errors.load(Ordering::SeqCst), 1);
            assert_eq!(dials.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn unpolled_loser_is_cancelled_without_vetoing_ready_winner() {
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let release = Arc::new(parking_lot::Mutex::new(Some(release)));
    let released = Arc::new(parking_lot::Mutex::new(Some(released)));
    let loser_polls = Arc::new(AtomicUsize::new(0));
    let cancellations = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<(), Node> = {
        let loser_polls = Arc::clone(&loser_polls);
        Arc::new(move |index, _| {
            if index == 0 {
                let released = released.lock().take().unwrap();
                Box::pin(async move {
                    released.await.unwrap();
                    Ok(())
                })
            } else {
                let loser_polls = Arc::clone(&loser_polls);
                Box::pin(async move {
                    loser_polls.fetch_add(1, Ordering::SeqCst);
                    Err(honk_outbound::proxy::PacketRejection::Capacity.into())
                })
            }
        })
    };
    let callbacks = UdpStaggerCallbacks {
        // A wakes while the loser is admitted, before it is pushed.
        allows_target: Arc::new(move |node: &Node| {
            if node.name == "loser" {
                let _ = release.lock().take().unwrap().send(());
            }
            true
        }),
        is_eligible: Arc::new(|_| true),
        on_dial_error: Arc::new(|_, _| panic!("cancellation is health-neutral")),
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: {
            let cancellations = Arc::clone(&cancellations);
            Arc::new(move || {
                cancellations.fetch_add(1, Ordering::SeqCst);
            })
        },
    };
    let task = tokio::spawn(prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![candidate("winner"), candidate("loser")],
        tokio::time::Instant::now() + Duration::from_secs(1),
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    let winner = task.await.unwrap().unwrap().unwrap();

    assert_eq!(winner.0.name, "winner");
    assert_eq!(loser_polls.load(Ordering::SeqCst), 0);
    assert_eq!(cancellations.load(Ordering::SeqCst), 1);
}
