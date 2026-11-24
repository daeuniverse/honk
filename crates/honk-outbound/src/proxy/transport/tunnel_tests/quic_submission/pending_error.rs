use super::*;
use crate::proxy::{PacketRejection, packet_rejection, socks5::Socks5Handler};
use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};

const CONNECT: [u8; 10] = [5, 1, 0, 1, 127, 0, 0, 1, 1, 187];
type Observations = Arc<Mutex<Vec<(FlowContext, Milestone)>>>;

fn observer_with_release(
    context: FlowContext,
    events: &Observations,
    changed: &Arc<Notify>,
) -> (FlowObserver, oneshot::Sender<()>) {
    let (released, lifetime) = oneshot::channel();
    let events = events.clone();
    let changed = changed.clone();
    let observer = FlowObserver::new(
        context,
        Arc::new(move |ctx, event| {
            // Releasing the last observer callback closes the channel.
            let _lifetime = &lifetime;
            if let FlowEvent::Milestone { milestone } = event {
                events.lock().push((ctx, milestone));
                changed.notify_one();
            }
        }),
    );
    (observer, released)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Confirmed,
    Uncertain,
    StreamReset,
    EndpointClosed,
    Cancelled,
}

#[tokio::test(flavor = "current_thread")]
async fn quic_setup_error_precedes_pending_socket_verdict() {
    for end in [
        End::Confirmed,
        End::Uncertain,
        End::StreamReset,
        End::EndpointClosed,
    ] {
        timeout(TIMEOUT, setup_with_pending_verdict(end))
            .await
            .unwrap_or_else(|_| panic!("pending socket verdict case timed out: {end:?}"));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn quic_explicit_cancel_erases_pending_socket_verdict() {
    timeout(TIMEOUT, setup_with_pending_verdict(End::Cancelled))
        .await
        .expect("explicit cancellation did not settle the pending verdict");
}

async fn setup_with_pending_verdict(end: End) {
    let (endpoint, client, server, gate) = connected_with_endpoint().await;
    // An endpoint close ends all its connections, so that row has a separate sibling.
    let other = if end == End::EndpointClosed {
        Some(connected().await)
    } else {
        None
    };
    let (sibling_client, sibling_server, sibling_gate) = other
        .as_ref()
        .map_or((&client, &server, &gate), |(client, server, gate)| {
            (client, server, gate)
        });
    let mut sibling = stream(sibling_client).await;
    sibling.write_all(b"W").await.unwrap();
    let (mut sibling_reply, mut sibling_rx) = sibling_server.accept_bi().await.unwrap();
    let mut marker = [0];
    sibling_rx.read_exact(&mut marker).await.unwrap();
    assert_eq!(&marker, b"W");

    let original_ctx = FlowContext {
        flow_id: uuid::Uuid::new_v4(),
        generation: 1,
        attempt_id: Some(uuid::Uuid::new_v4()),
        lookup_id: Some(uuid::Uuid::new_v4()),
        dns_purpose: "proxy_server",
    };
    let sibling_ctx = FlowContext {
        attempt_id: Some(uuid::Uuid::new_v4()),
        lookup_id: Some(uuid::Uuid::new_v4()),
        ..original_ctx
    };
    let events = Observations::default();
    let changed = Arc::new(Notify::new());
    let (original, mut released) = observer_with_release(original_ctx, &events, &changed);
    let physical_drops = Arc::new(AtomicUsize::new(0));
    let drops = physical_drops.clone();
    let (send, recv) = client.open_bi().await.unwrap();
    let id = send.id();
    let physical = QuicBiStream::new(send, recv).with_on_drop(move || {
        drops.fetch_add(1, Relaxed);
    });
    let mut retained = Retained(Arc::new(Mutex::new(physical)));
    let carrier = retained.clone();
    let (cancel, cancelled) = oneshot::channel();
    let foreground = original.scope(observe_chain_request(async move {
        let node = crate::test_support::socks5("socks", "127.0.0.1", 1080);
        let dial = Socks5Handler.dial_over(
            crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap(),
            Box::new(carrier),
            "127.0.0.1:443".parse().unwrap(),
            None,
            TunnelDialOptions::new(TIMEOUT),
        );
        tokio::select! {
            result = dial => result,
            Ok(()) = cancelled => Err(PacketRejection::Cancelled.into()),
        }
    }));
    drop(original);
    let peer = async {
        let (mut reply, mut rx) = server.accept_bi().await.unwrap();
        assert_eq!(rx.id(), id);
        let mut greeting = [0; 3];
        rx.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        reply.write_all(&[5, 0]).await.unwrap();
        gate.held().await;
        let mut byte = [0];
        assert!(futures_util::poll!(std::pin::pin!(rx.read(&mut byte))).is_pending());
        if end == End::Cancelled {
            cancel.send(()).unwrap();
        } else {
            // EOF on the response half while the peer can still receive CONNECT.
            reply.finish().unwrap();
        }
        (reply, rx)
    };
    let (result, (_reply, mut rx)) = tokio::join!(foreground, peer);
    let error = result.unwrap_err();
    assert_eq!(*gate.permit.lock(), Permit::Held);
    assert_eq!(gate.strict.load(Relaxed), 0);
    assert!(events.lock().is_empty());
    assert_eq!(physical_drops.load(Relaxed), 0);
    if end == End::Cancelled {
        assert_eq!(packet_rejection(&error), Some(PacketRejection::Cancelled));
        released.closed().await;
    } else {
        assert_eq!(packet_rejection(&error), None);
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::UnexpectedEof,
        );
        assert!(
            !released.is_closed(),
            "ordinary EOF discarded the pending receipt"
        );
    }

    let code = quinn::VarInt::from_u32(23);
    match end {
        End::Confirmed | End::Uncertain | End::Cancelled => {
            gate.release((end != End::Cancelled).then_some(end == End::Confirmed));
            let mut connect = [0; CONNECT.len()];
            rx.read_exact(&mut connect).await.unwrap();
            assert_eq!(connect, CONNECT);
            released.closed().await;
            retained.shutdown().await.unwrap();
            drop(retained);
            assert!(rx.read_to_end(0).await.unwrap().is_empty());
        }
        End::StreamReset => {
            let physical = Arc::try_unwrap(retained.0).unwrap().into_inner();
            let (mut send, _recv, _guard) = physical.into_parts();
            send.reset(code).unwrap();
            released.closed().await;
            gate.release(None);
            assert_eq!(rx.received_reset().await.unwrap(), Some(code));
        }
        End::EndpointClosed => {
            endpoint.close(code, b"fixture closed");
            assert!(matches!(
                client.closed().await,
                quinn::ConnectionError::LocallyClosed
            ));
            released.closed().await;
            drop(retained);
            gate.release(None);
            assert!(matches!(
                server.closed().await,
                quinn::ConnectionError::ApplicationClosed(close) if close.error_code == code
            ));
            endpoint.wait_idle().await;
        }
    }
    let strict_send = matches!(end, End::Confirmed | End::Uncertain);
    assert_eq!(
        gate.strict.load(Relaxed),
        usize::from(strict_send),
        "{end:?}"
    );
    assert_eq!(physical_drops.load(Relaxed), 1, "{end:?}");
    let mut expected = Vec::new();
    if end == End::Confirmed {
        expected.push((original_ctx, Milestone::TargetRequestSent));
    }
    assert_eq!(*events.lock(), expected, "{end:?}");

    sibling_gate.release(None);
    let (observer, mut sibling_released) = observer_with_release(sibling_ctx, &events, &changed);
    let mut tunnel = observer
        .scope(observe_chain_request(trojan(sibling)))
        .await
        .unwrap();
    drop(observer);
    tunnel.stream.shutdown().await.unwrap();
    assert_eq!(sibling_rx.read_to_end(TROJAN.len()).await.unwrap(), TROJAN);
    sibling_reply.write_all(b"R").await.unwrap();
    sibling_reply.finish().unwrap();
    assert_eq!(tunnel.stream.read_u8().await.unwrap(), b'R');
    let sibling_sent = (sibling_ctx, Milestone::TargetRequestSent);
    while !events.lock().contains(&sibling_sent) {
        changed.notified().await;
    }
    drop(tunnel);
    sibling_released.closed().await;
    expected.push(sibling_sent);
    assert_eq!(*events.lock(), expected, "{end:?}");
}
