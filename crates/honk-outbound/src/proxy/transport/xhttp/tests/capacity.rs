use super::*;

#[tokio::test]
async fn drop_cancels_pending_requests_and_releases_logical_permits() {
    for mode in [
        XhttpMode::PacketUp,
        XhttpMode::StreamUp,
        XhttpMode::StreamOne,
    ] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(1).await;
            let owner = peer.runtime(mode, 8);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let mut download = peer.next().await;
            let mut upload = if mode == XhttpMode::StreamUp {
                Some(peer.next().await)
            } else {
                None
            };
            if mode == XhttpMode::PacketUp {
                stream.write_all(b"pending").await.unwrap();
                upload = Some(peer.next().await);
            }
            assert!(upload_pool(&runtime).metrics().streams > 0);
            drop(stream);
            wait_released(&runtime).await;
            assert_eq!(
                poll_fn(|cx| download.respond.poll_reset(cx)).await.unwrap(),
                h2::Reason::CANCEL
            );
            if let Some(upload) = &mut upload {
                assert_eq!(
                    poll_fn(|cx| upload.respond.poll_reset(cx)).await.unwrap(),
                    h2::Reason::CANCEL
                );
            }
            let mut replacement = open(&runtime).await;
            let mut next = peer.next().await;
            assert!(
                next.carrier == download.carrier
                    || upload
                        .as_ref()
                        .is_some_and(|upload| next.carrier == upload.carrier),
                "logical drop unnecessarily killed a reusable socket"
            );
            let _replacement_upload = if mode == XhttpMode::StreamUp {
                Some(peer.next().await)
            } else {
                None
            };
            let mut reply = response(&mut next.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"reused"), true).await;
            let mut received = Vec::new();
            replacement.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"reused");
            drop(replacement);
            wait_released(&runtime).await;
        })
        .await
        .unwrap_or_else(|_| panic!("request cancellation leaked for {mode:?}"));
    }
}

#[tokio::test]
async fn logical_capacity_refusal_does_not_dial_and_drop_returns_admission() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(32).await;
        let owner = peer.runtime(XhttpMode::StreamOne, 32);
        let runtime = owner.runtime();
        let mut streams = Vec::new();
        let mut requests = Vec::new();
        for _ in 0..MAX_REQUESTS {
            streams.push(open(&runtime).await);
            requests.push(peer.next().await);
        }
        let carriers: std::collections::HashSet<_> =
            requests.iter().map(|request| request.carrier).collect();
        assert!((1..=2).contains(&carriers.len()));
        let transport = runtime.xhttp.as_ref().unwrap();
        let before_refusal = transport.upload.pool.live_session_count();
        assert_eq!(transport.upload.pool.metrics().streams, MAX_REQUESTS);
        let refused = transport.open(&runtime, None, DEADLINE).await;
        let error = match refused {
            Err(error) => error,
            Ok(_) => panic!("logical flow bound was bypassed"),
        };
        assert!(error.chain().any(|cause| matches!(
            cause.downcast_ref::<crate::proxy::PacketRejection>(),
            Some(crate::proxy::PacketRejection::Capacity)
        )));
        assert_eq!(transport.upload.pool.live_session_count(), before_refusal);
        assert!(
            peer.requests.try_recv().is_err(),
            "capacity refusal issued a request"
        );
        let released = streams.pop().unwrap();
        drop(released);
        let mut cancelled = requests.pop().unwrap();
        assert_eq!(
            poll_fn(|cx| cancelled.respond.poll_reset(cx))
                .await
                .unwrap(),
            h2::Reason::CANCEL
        );
        let replacement = open(&runtime).await;
        let _replacement_request = peer.next().await;
        drop(replacement);
        drop(streams);
        wait_released(&runtime).await;
        let sessions = transport.upload.pool.live_session_count();
        assert!((1..=2).contains(&sessions));
    })
    .await
    .expect("logical capacity did not recover after cancellation");
}

#[tokio::test]
async fn cancelling_open_behind_two_full_peer_carriers_returns_admission_without_a_request() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::with_stream_limit(32, 1).await;
        let owner = peer.runtime(XhttpMode::StreamOne, 32);
        let runtime = owner.runtime();
        let mut first = open(&runtime).await;
        let mut active = peer.next().await;
        let mut first_reply = response(&mut active.respond, 200, false);
        send(&mut first_reply, Bytes::from_static(b"ready"), false).await;
        let mut ready = [0; 5];
        first.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"ready");
        let mut second = open(&runtime).await;
        let mut other = peer.next().await;
        assert_ne!(other.carrier, active.carrier);
        let mut second_reply = response(&mut other.respond, 200, false);
        send(&mut second_reply, Bytes::from_static(b"ready"), false).await;
        second.read_exact(&mut ready).await.unwrap();
        let transport = runtime.xhttp.as_ref().unwrap();
        let mut pending = Box::pin(transport.open(&runtime, None, DEADLINE));
        poll_fn(|cx| {
            assert!(
                pending.as_mut().poll(cx).is_pending(),
                "full peer carriers did not block establishment"
            );
            Poll::Ready(())
        })
        .await;
        assert!(
            peer.requests.try_recv().is_err(),
            "pending open bypassed peer concurrency"
        );
        drop(pending);
        drop(second);
        assert_eq!(
            poll_fn(|cx| second_reply.poll_reset(cx)).await.unwrap(),
            h2::Reason::CANCEL
        );
        let mut replacement = open(&runtime).await;
        let mut request = peer.next().await;
        assert_eq!(request.carrier, other.carrier);
        let client = async {
            replacement.write_all(b"fresh").await.unwrap();
            replacement.shutdown().await.unwrap();
        };
        let server = async {
            assert_eq!(receive(request.request.body_mut(), 5).await, b"fresh");
            eof(request.request.body_mut()).await;
        };
        tokio::join!(client, server);
        assert!(
            peer.requests.try_recv().is_err(),
            "cancelled pending open published a request later"
        );
        assert_eq!(transport.upload.pool.live_session_count(), 2);
        drop(replacement);
        drop(first);
        assert_eq!(
            poll_fn(|cx| first_reply.poll_reset(cx)).await.unwrap(),
            h2::Reason::CANCEL
        );
        wait_released(&runtime).await;
    })
    .await
    .expect("pending establishment cancellation failed to return H2/logical capacity");
}

#[tokio::test]
async fn one_stream_peer_uses_second_carrier_for_upload_without_blocking_active_get() {
    for mode in [XhttpMode::PacketUp, XhttpMode::StreamUp] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::with_stream_limit(32, 1).await;
            let owner = peer.runtime(mode, 32);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let mut download = peer.next().await;
            assert_eq!(download.request.method(), http::Method::GET);
            let path = session_path(&download.request);
            let server = async {
                let mut upload = peer.next().await;
                assert_ne!(
                    upload.carrier, download.carrier,
                    "upload queued behind the active GET instead of using the second carrier"
                );
                assert_eq!(upload.request.method(), http::Method::POST);
                assert_eq!(
                    upload.request.uri().path(),
                    if mode == XhttpMode::PacketUp {
                        format!("{path}/0")
                    } else {
                        path.clone()
                    }
                );
                assert_eq!(receive(upload.request.body_mut(), 3).await, b"raw");
                eof(upload.request.body_mut()).await;
                response(&mut upload.respond, 200, true);
                let mut reply = response(&mut download.respond, 200, false);
                send(&mut reply, Bytes::from_static(b"both-carriers"), true).await;
            };
            let client = async {
                stream.write_all(b"raw").await.unwrap();
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"both-carriers");
            };
            tokio::join!(server, client);
            assert_eq!(upload_pool(&runtime).live_session_count(), 2);
            assert!(
                peer.requests.try_recv().is_err(),
                "bounded upload was replayed"
            );
        })
        .await
        .unwrap_or_else(|_| panic!("one-stream peer deadlocked {mode:?} GET and POST"));
    }
}
