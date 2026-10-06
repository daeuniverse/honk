use super::*;

#[tokio::test]
async fn clean_goaway_preserves_an_already_flushed_upload() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(32).await;
        let tcp = TcpStream::connect(peer.address).await.unwrap();
        let session = connect(Box::new(tcp)).await.unwrap();
        let permit = session.try_reserve().unwrap();
        let mut request = Some(http::Request::post("http://peer/upload").body(()).unwrap());
        let request = session
            .clone()
            .request(RequestOwner::Pool { _permit: permit }, &mut request, false)
            .await
            .unwrap_or_else(|_| panic!("failed to admit peer request"));
        let mut upload = UploadRequest {
            send: request.send,
            _permit: request.permit,
            session: session.clone(),
            response: None,
            pending: Arc::new(AtomicUsize::new(0)),
        };
        let mut body = Box::pin(send_body(
            &mut upload,
            Bytes::from_static(b"confirmed"),
            true,
        ));
        assert!(futures_util::poll!(&mut body).is_pending());
        let mut request_peer = peer.next().await;
        assert_eq!(
            receive(request_peer.request.body_mut(), 9).await,
            b"confirmed"
        );
        eof(request_peer.request.body_mut()).await;
        response(&mut request_peer.respond, 200, true);
        let (ack, received) = oneshot::channel();
        request_peer
            .control
            .send(PeerCommand::Goaway(ack))
            .await
            .unwrap();
        received.await.unwrap();
        drain_response(request.response, session.clone())
            .await
            .unwrap();
        // Repoll only after clean termination wins the driver's scheduling race.
        while !session.is_clean_end() {
            tokio::task::yield_now().await;
        }
        body.await.unwrap();
    })
    .await
    .expect("graceful GOAWAY did not settle a confirmed upload");
}

#[tokio::test]
async fn graceful_goaway_rotates_carrier_without_replay_and_keeps_active_get() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(32).await;
        let owner = peer.runtime(XhttpMode::PacketUp, 32);
        let runtime = owner.runtime();
        let mut stream = open(&runtime).await;
        let mut old_download = peer.next().await;
        let path = session_path(&old_download.request);
        let old_session = carrier(&runtime).await;
        let mut old_reply = response(&mut old_download.respond, 200, false);
        send(&mut old_reply, Bytes::from_static(b"before-"), false).await;
        let mut before = [0; 7];
        stream.read_exact(&mut before).await.unwrap();
        assert_eq!(&before, b"before-");
        let (ack, received) = oneshot::channel();
        old_download
            .control
            .send(PeerCommand::Goaway(ack))
            .await
            .unwrap();
        received.await.unwrap();
        while old_session.state() == SessionState::Active {
            tokio::task::yield_now().await;
        }
        assert_eq!(old_session.state(), SessionState::Draining);
        let server = async {
            let mut upload = peer.next().await;
            assert_ne!(upload.carrier, old_download.carrier);
            assert_eq!(upload.request.uri().path(), format!("{path}/0"));
            assert_eq!(receive(upload.request.body_mut(), 6).await, b"unique");
            eof(upload.request.body_mut()).await;
            response(&mut upload.respond, 200, true);
            send(&mut old_reply, Bytes::from_static(b"after"), true).await;
        };
        let client = async {
            stream.write_all(b"unique").await.unwrap();
            stream.flush().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut after = Vec::new();
            stream.read_to_end(&mut after).await.unwrap();
            assert_eq!(after, b"after");
        };
        tokio::join!(server, client);
        assert!(
            peer.requests.try_recv().is_err(),
            "GOAWAY replayed GET or application bytes"
        );
        drop(stream);
        wait_released(&runtime).await;
        assert_eq!(old_session.state(), SessionState::Closed);
    })
    .await
    .expect("GOAWAY rotation interrupted active download or replayed upload");
}
