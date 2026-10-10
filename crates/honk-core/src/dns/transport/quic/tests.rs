use super::*;
use std::{net::SocketAddr, sync::Arc};

use honk_config::types::DnsProtocol;
use honk_outbound::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
use parking_lot::Mutex;
use uuid::Uuid;

use crate::dns::transport::tests_proto::{insecure_quic_config, quic_server_endpoint};

type CapturedEvents = Arc<Mutex<Vec<(FlowContext, FlowEvent)>>>;

fn direct(address: SocketAddr, protocol: DnsProtocol) -> DialContext {
    DialContext {
        endpoint: DnsEndpoint::parse(&address.to_string(), protocol, Some("localhost")).unwrap(),
        query_timeout: Duration::from_secs(2),
        dial_timeout: Duration::from_secs(2),
        proxy: None,
    }
}

fn capture() -> (FlowObserver, CapturedEvents) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let observer = FlowObserver::new(
        FlowContext {
            flow_id: Uuid::new_v4(),
            generation: 37,
            attempt_id: Some(Uuid::new_v4()),
            lookup_id: Some(Uuid::new_v4()),
            dns_purpose: "dial_target",
        },
        Arc::new(move |context, event| captured.lock().push((context, event))),
    );
    (observer, events)
}

fn assert_handshake(
    events: &[(FlowContext, FlowEvent)],
    context: FlowContext,
    address: SocketAddr,
    expected_status: &str,
) {
    let [
        (
            started_context,
            FlowEvent::Transport {
                attempt_id: started_id,
                server_addr: started_address,
                status: honk_outbound::runtime::flow_observation::TransportStatus::Started,
                error: None,
                ..
            },
        ),
        (
            finished_context,
            FlowEvent::Transport {
                attempt_id: finished_id,
                server_addr: finished_address,
                status,
                error,
                ..
            },
        ),
    ] = events
    else {
        panic!("expected one physical handshake lifecycle, got {events:?}");
    };
    assert_eq!(*started_context, context);
    assert_eq!(*finished_context, context);
    assert_eq!(started_id, finished_id);
    assert_ne!(Some(*started_id), context.attempt_id);
    assert_eq!(*started_address, Some(address));
    assert_eq!(*finished_address, Some(address));
    assert_eq!(status.as_str(), expected_status);
    assert_eq!(
        error.map(|error| error.as_str()),
        match expected_status {
            "succeeded" => None,
            "cancelled" => Some("cancelled"),
            _ => Some("quic_connect_failed"),
        }
    );
}

#[tokio::test]
async fn literal_doq_and_doh3_handshakes_record_actual_success_and_failure() {
    for (protocol, alpn, label) in [
        (DnsProtocol::Quic, b"doq".as_slice(), "DoQ"),
        (DnsProtocol::H3, b"h3".as_slice(), "DoH3 QUIC"),
    ] {
        for succeeds in [true, false] {
            let (server, address) = quic_server_endpoint(if succeeds { alpn } else { b"mismatch" });
            let dial = direct(address, protocol);
            let endpoint = SharedQuicEndpoint::new();
            let config = insecure_quic_config(alpn).await;
            let (observer, events) = capture();
            let (client, accepted) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(
                    observer.scope(quic_connect_endpoint(
                        &dial,
                        &endpoint,
                        &config,
                        &dial.endpoint,
                        tokio::time::Instant::now() + dial.dial_timeout,
                        label,
                    )),
                    async { server.accept().await.unwrap().await },
                )
            })
            .await
            .unwrap();
            if succeeds {
                let (connection, owner) = client.unwrap();
                let accepted = accepted.unwrap();
                assert!(owner.is_none());
                connection.close(0_u32.into(), b"done");
                accepted.close(0_u32.into(), b"done");
            } else {
                assert!(client.is_err());
                assert!(accepted.is_err());
            }
            assert_handshake(
                &events.lock(),
                observer.context(),
                address,
                if succeeds { "succeeded" } else { "failed" },
            );
            endpoint.close(Duration::from_secs(1)).await;
            server.close(0_u32.into(), b"done");
        }
    }
}

#[tokio::test]
async fn literal_doq_and_doh3_cancel_after_wire_start_keep_parent_and_lookup() {
    for (protocol, alpn, label) in [
        (DnsProtocol::Quic, b"doq".as_slice(), "DoQ"),
        (DnsProtocol::H3, b"h3".as_slice(), "DoH3 QUIC"),
    ] {
        let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = sink.local_addr().unwrap();
        let dial = direct(address, protocol);
        let endpoint = SharedQuicEndpoint::new();
        let config = insecure_quic_config(alpn).await;
        let (observer, events) = capture();
        {
            let connecting = observer.scope(quic_connect_endpoint(
                &dial,
                &endpoint,
                &config,
                &dial.endpoint,
                tokio::time::Instant::now() + dial.dial_timeout,
                label,
            ));
            tokio::pin!(connecting);
            let mut packet = [0; 2048];
            tokio::select! {
                result = &mut connecting => panic!("handshake finished before cancellation: {result:?}"),
                received = tokio::time::timeout(Duration::from_secs(1), sink.recv_from(&mut packet)) => {
                    assert!(received.unwrap().unwrap().0 >= 1200);
                }
            }
        }
        assert_handshake(&events.lock(), observer.context(), address, "cancelled");
        endpoint.close(Duration::from_secs(1)).await;
    }
}
