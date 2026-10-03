use super::*;
use crate::proxy::TcpOutbound;
use honk_config::node::{Node, OutboundConfig};
use parking_lot::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Events = Arc<Mutex<Vec<(FlowContext, FlowEvent)>>>;

fn recorder() -> (FlowObserver, Events) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&events);
    let observer = FlowObserver::new(
        FlowContext {
            flow_id: Uuid::new_v4(),
            generation: 7,
            attempt_id: Some(Uuid::new_v4()),
            lookup_id: None,
            dns_purpose: "proxy_server",
        },
        Arc::new(move |context, event| output.lock().push((context, event))),
    );
    (observer, events)
}

#[tokio::test]
async fn physical_tcp_attempts_finish_once_with_distinct_child_ids() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (observer, events) = recorder();
    let timeout = Duration::from_secs(1);
    observer
        .scope(async {
            let stream = crate::util::connect_marked_addr(address, None, timeout)
                .await
                .unwrap();
            let (peer, _) = listener.accept().await.unwrap();
            drop((stream, peer));
            // The socket stays bound but does not listen, so no unrelated process can take the port.
            let refused =
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
            refused
                .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
                .unwrap();
            let refused_address = refused.local_addr().unwrap().as_socket().unwrap();
            assert!(
                crate::util::connect_marked_addr(refused_address, None, timeout)
                    .await
                    .is_err()
            );
            let mut cancelled = Box::pin(crate::util::connect_marked_addr(address, None, timeout));
            assert!(futures_util::poll!(&mut cancelled).is_pending());
            drop(cancelled);
        })
        .await;
    let events = events.lock();
    let attempts: Vec<_> = events
        .iter()
        .filter_map(|(context, event)| match event {
            FlowEvent::Transport {
                attempt_id, status, ..
            } => {
                assert_eq!(context.attempt_id, observer.context().attempt_id);
                assert_ne!(Some(*attempt_id), context.attempt_id);
                Some((*attempt_id, status.as_str()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        attempts
            .iter()
            .map(|(_, status)| *status)
            .collect::<Vec<_>>(),
        [
            "started",
            "succeeded",
            "started",
            "failed",
            "started",
            "cancelled"
        ]
    );
    for pair in attempts.as_chunks::<2>().0 {
        assert_eq!(pair[0].0, pair[1].0);
    }
    assert_ne!(attempts[0].0, attempts[2].0);
    assert_ne!(attempts[2].0, attempts[4].0);
}

#[tokio::test]
async fn exclusive_child_inherits_but_autonomous_and_unobserved_work_do_not() {
    let (observer, events) = recorder();
    assert!(
        TransportAttempt::start(
            None,
            crate::runtime::flow_observation::ResolutionLocation::Unknown
        )
        .is_none()
    );
    observer
        .scope(async {
            let captured = crate::runtime::capture_dial_scope();
            let child = tokio::spawn(captured.clone().scope(async {
                milestone(crate::runtime::flow_observation::Milestone::TransportReady);
            }));
            child.await.unwrap();
            crate::runtime::capture_dial_admission()
                .scope(captured.clone().scope(async {
                    assert!(current().is_none());
                    assert!(
                        TransportAttempt::start(
                            None,
                            crate::runtime::flow_observation::ResolutionLocation::Unknown
                        )
                        .is_none()
                    );
                    milestone(crate::runtime::flow_observation::Milestone::TargetConfirmed);
                    crate::runtime::admit_physical_dial(async { Ok::<_, ()>(()) })
                        .await
                        .unwrap();
                }))
                .await;
            without(async {
                tokio::spawn(captured.scope(async {
                    assert!(current().is_none());
                    milestone(crate::runtime::flow_observation::Milestone::TargetConfirmed);
                }))
                .await
                .unwrap();
            })
            .await;
            assert_eq!(
                current().unwrap().context().flow_id,
                observer.context().flow_id
            );
            without(observer.scope(async {
                assert!(current().is_none());
            }))
            .await;
        })
        .await;
    assert!(current().is_none());
    let events = events.lock();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].1,
        FlowEvent::Milestone {
            milestone: crate::runtime::flow_observation::Milestone::TransportReady
        }
    ));
}

#[tokio::test]
async fn socks_connect_confirms_only_a_complete_success_reply() {
    for reply in [0, 5] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 1]);
            request_tx.send(()).unwrap();
            release_rx.await.unwrap();
            stream
                .write_all(&[5, reply, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        let node = Node {
            address: address.ip().to_string(),
            port: address.port(),
            outbound: OutboundConfig::Socks5(Default::default()),
            ..Default::default()
        };
        let (observer, events) = recorder();
        let dial = tokio::spawn(async move {
            observer
                .scope(crate::proxy::socks5::Socks5Handler::new().dial(
                    &node,
                    "127.0.0.1:80".parse().unwrap(),
                    None,
                    Duration::from_secs(1),
                ))
                .await
        });
        request_rx.await.unwrap();
        assert!(events.lock().iter().any(|(_, event)| matches!(
            event,
            FlowEvent::Milestone {
                milestone: crate::runtime::flow_observation::Milestone::TargetRequestSent
            }
        )));
        assert!(!events.lock().iter().any(|(_, event)| matches!(
            event,
            FlowEvent::Milestone {
                milestone: crate::runtime::flow_observation::Milestone::TargetConfirmed
            }
        )));
        release_tx.send(()).unwrap();
        assert_eq!(dial.await.unwrap().is_ok(), reply == 0);
        server.await.unwrap();
        assert_eq!(
            events
                .lock()
                .iter()
                .filter(|(_, event)| matches!(
                    event,
                    FlowEvent::Milestone {
                        milestone: crate::runtime::flow_observation::Milestone::TargetConfirmed
                    }
                ))
                .count(),
            usize::from(reply == 0)
        );
    }
}

#[tokio::test]
async fn trojan_header_write_does_not_fabricate_target_confirmation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = "127.0.0.1:80".parse().unwrap();
    let node = Node {
        address: address.ip().to_string(),
        port: address.port(),
        outbound: OutboundConfig::Trojan(Default::default()),
        ..Default::default()
    };
    let (observer, events) = recorder();
    let tcp = TcpStream::connect(address).await.unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let stream = observer
        .scope(crate::proxy::trojan::TrojanHandler::new().dial_with_tcp(
            &node,
            target,
            None,
            tcp,
            Duration::from_secs(1),
        ))
        .await
        .unwrap();
    let mut header = [0; 68];
    peer.read_exact(&mut header).await.unwrap();
    assert_eq!(&header[56..59], b"\r\n\x01");
    assert!(events.lock().iter().any(|(_, event)| matches!(
        event,
        FlowEvent::Milestone {
            milestone: crate::runtime::flow_observation::Milestone::TargetRequestSent
        }
    )));
    assert!(!events.lock().iter().any(|(_, event)| matches!(
        event,
        FlowEvent::Milestone {
            milestone: crate::runtime::flow_observation::Milestone::TargetConfirmed
        }
    )));
    drop(stream);
}

#[tokio::test]
async fn hosts_fallback_resolution_reports_only_known_facts() {
    let (observer, events) = recorder();
    let addresses = observer
        .scope(crate::bootstrap::resolve_with(None, "localhost"))
        .await
        .unwrap();
    assert!(!addresses.is_empty());
    let events = events.lock();
    assert!(
        !events
            .iter()
            .any(|(_, event)| matches!(event, FlowEvent::Gap(_)))
    );
    let lookups: Vec<_> = events
        .iter()
        .filter_map(|(_, event)| match event {
            FlowEvent::Dns(lookup) => Some(lookup),
            _ => None,
        })
        .collect();
    assert_eq!(lookups.len(), 2);
    assert_eq!(lookups[0].lookup_id, lookups[1].lookup_id);
    assert_eq!(lookups[0].status, "started");
    let lookup = lookups[1];
    assert_eq!(lookup.status, "succeeded");
    assert_eq!(lookup.source, "hosts");
    assert_eq!(lookup.cache, "bypass");
    assert!(lookup.upstream.is_none());
    assert!(lookup.upstream_transport.is_none());
    assert!(lookup.carrier_transport.is_none());
    assert!(lookup.selected_ip.is_none());
    assert_eq!(lookup.addresses, addresses);
}

#[test]
fn shared_milestones_are_once_per_causal_context_not_once_per_carrier() {
    let (observer, events) = recorder();
    let mut dns_context = observer.context();
    dns_context.lookup_id = Some(Uuid::new_v4());
    dns_context.dns_purpose = "dial_target";
    let dns = observer.with_context(dns_context);
    dns.milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
    dns.clone()
        .milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
    observer.milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
    observer
        .clone()
        .milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
    observer
        .with_context(observer.context())
        .milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
    let mut context = observer.context();
    context.attempt_id = Some(Uuid::new_v4());
    observer
        .with_context(context)
        .milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
    let events = events.lock();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].0, dns_context);
    assert_eq!(events[1].0, observer.context());
    assert_eq!(events[2].0, context);
}
