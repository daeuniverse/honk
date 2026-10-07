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

#[tokio::test]
async fn packet_up_replacement_obeys_the_published_successor_admission() {
    use crate::runtime::OutboundRuntimeRegistry;

    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(32).await;
        let mut node = node(XhttpMode::PacketUp, 32);
        node.address = peer.address.ip().to_string();
        node.port = peer.address.port();
        node.normalize_stream_transport().unwrap();
        node.id = node.derive_id();
        let (first, _) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node), 1, 4, 4, None,
        )
        .unwrap();
        first.activate_background_dial_admission();
        let runtime = first.get(&node.id).unwrap();
        first
            .scope_dials(XhttpRuntime::warm(&runtime, DEADLINE))
            .await
            .unwrap();
        peer.wait_settings(&runtime).await;
        let mut stream = first.scope_dials(open(&runtime)).await;
        let mut download = peer.next().await;
        let old_session = carrier(&runtime).await;
        let _reply = response(&mut download.respond, 200, false);

        let (successor, moved) = OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
            std::slice::from_ref(&node), 1, 4, 4, Some(&first),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&runtime, &successor.get(&node.id).unwrap()));
        successor.activate_background_dial_admission();
        first.mark_moved_out(moved);
        first.retire_reusable_state().await;
        let successor_held = successor.acquire_dial_permit().await;

        let (ack, received) = oneshot::channel();
        download.control.send(PeerCommand::Goaway(ack)).await.unwrap();
        received.await.unwrap();
        while old_session.state() == SessionState::Active {
            tokio::task::yield_now().await;
        }
        assert_eq!(old_session.state(), SessionState::Draining);
        stream.write_all(b"unique").await.unwrap();
        if let Ok(request) =
            tokio::time::timeout(Duration::from_millis(100), peer.requests.recv()).await
        {
            let request = request.expect("H2 peer stopped during replacement admission");
            panic!(
                "packet-up replacement bypassed the successor's physical-dial limit: carrier {}, GET carrier {}, URI {}",
                request.carrier, download.carrier, request.request.uri()
            );
        }

        let predecessor_held = first.acquire_dial_permit().await;
        drop(successor_held);
        let mut upload = peer.next().await;
        assert_ne!(upload.carrier, download.carrier);
        assert_eq!(receive(upload.request.body_mut(), 6).await, b"unique");
        eof(upload.request.body_mut()).await;
        response(&mut upload.respond, 200, true);
        stream.flush().await.unwrap();
        drop(predecessor_held);
        drop(stream);
        successor.shutdown().await;
    })
    .await
    .expect("packet-up replacement retained the predecessor's admission");
}

#[tokio::test]
async fn cancelled_requests_keep_late_frames_from_closing_a_live_carrier() {
    async fn frame(tcp: &mut TcpStream) -> io::Result<(u8, u8, u32, Vec<u8>)> {
        let mut header = [0; 9];
        tcp.read_exact(&mut header).await?;
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let id = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
        let mut payload = vec![0; length];
        tcp.read_exact(&mut payload).await?;
        Ok((header[3], header[4], id, payload))
    }
    async fn send_frame(
        tcp: &mut TcpStream,
        kind: u8,
        flags: u8,
        id: u32,
        bytes: &[u8],
    ) -> io::Result<()> {
        let length = (bytes.len() as u32).to_be_bytes();
        let id = id.to_be_bytes();
        tcp.write_all(&[
            length[1], length[2], length[3], kind, flags, id[0], id[1], id[2], id[3],
        ])
        .await?;
        tcp.write_all(bytes).await
    }

    tokio::time::timeout(DEADLINE, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted, mut all_accepted) = mpsc::channel(1);
        let (finished, finish) = oneshot::channel();
        // h2's server API cannot emit frames after observing a reset; raw frames model frames already in flight.
        let peer = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await?;
            tcp.set_nodelay(true)?;
            let mut preface = [0; 24];
            tcp.read_exact(&mut preface).await?;
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            let (kind, flags, id, _) = frame(&mut tcp).await?;
            assert_eq!((kind, flags, id), (4, 0, 0));
            send_frame(&mut tcp, 4, 1, 0, &[]).await?;
            let limit = (MAX_REQUESTS as u32).to_be_bytes();
            send_frame(
                &mut tcp,
                4,
                0,
                0,
                &[0, 3, limit[0], limit[1], limit[2], limit[3]],
            )
            .await?;
            let live = loop {
                let (kind, _, id, _) = frame(&mut tcp).await?;
                if kind == 1 {
                    break id;
                }
            };
            send_frame(&mut tcp, 1, 4, live, &[0x88]).await?;
            send_frame(&mut tcp, 0, 0, live, b"before").await?;
            let mut cancelled = Vec::new();
            let mut resets = 0;
            while cancelled.len() < MAX_REQUESTS * 2 {
                let (kind, _, id, payload) = frame(&mut tcp).await?;
                if kind == 1 {
                    cancelled.push(id);
                    if cancelled.len().is_multiple_of(MAX_REQUESTS / 2) {
                        accepted.send(()).await.unwrap();
                    }
                } else if kind == 3 {
                    assert!(cancelled.contains(&id));
                    assert_eq!(payload, 8_u32.to_be_bytes());
                    resets += 1;
                }
            }
            while resets < cancelled.len() {
                let (kind, _, id, payload) = frame(&mut tcp).await?;
                if kind == 3 {
                    assert!(cancelled.contains(&id));
                    assert_eq!(payload, 8_u32.to_be_bytes());
                    resets += 1;
                }
            }
            for id in cancelled {
                send_frame(&mut tcp, 1, 4, id, &[0x88]).await?;
                send_frame(&mut tcp, 0, 1, id, b"late").await?;
            }
            send_frame(&mut tcp, 6, 0, 0, b"barrier!").await?;
            loop {
                let (kind, flags, _, payload) = frame(&mut tcp).await?;
                if kind == 7 || kind == 3 {
                    return Err(io::Error::other(format!(
                        "late cancelled frames caused H2 frame type {kind}: {payload:?}"
                    )));
                }
                if kind == 6 && flags == 1 {
                    assert_eq!(payload, b"barrier!");
                    break;
                }
            }
            send_frame(&mut tcp, 0, 1, live, b"after").await?;
            finish.await.unwrap();
            Ok::<_, io::Error>(())
        });
        let tcp = TcpStream::connect(address).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let session = connect(Box::new(tcp)).await.unwrap();
        let permit = session.try_reserve().unwrap();
        let mut request = Some(http::Request::get("http://peer/live").body(()).unwrap());
        let live = session
            .clone()
            .request(RequestOwner::Pool { _permit: permit }, &mut request, true)
            .await
            .unwrap_or_else(|_| panic!("live request admission failed"));
        let mut body = live.response.await.unwrap().into_body();
        let before = body.data().await.unwrap().unwrap();
        assert_eq!(before, b"before".as_slice());
        body.flow_control().release_capacity(before.len()).unwrap();
        for _ in 0..4 {
            let mut cancelled = Vec::new();
            for _ in 0..MAX_REQUESTS / 2 {
                let permit = session.try_reserve().unwrap();
                let mut request = Some(
                    http::Request::get("http://peer/cancelled")
                        .body(())
                        .unwrap(),
                );
                cancelled.push(
                    session
                        .clone()
                        .request(RequestOwner::Pool { _permit: permit }, &mut request, true)
                        .await
                        .unwrap_or_else(|_| panic!("cancelled request admission failed")),
                );
            }
            all_accepted.recv().await.unwrap();
            drop(cancelled);
        }
        let client = async {
            let after = body.data().await;
            let state = session.state();
            let _ = finished.send(());
            (after, state)
        };
        let ((after, state), result) = tokio::join!(client, peer);
        result
            .unwrap()
            .expect("late reset frames must not retire the shared carrier");
        assert_eq!(after.unwrap().unwrap(), b"after".as_slice());
        assert_eq!(state, SessionState::Active);
    })
    .await
    .expect("cancelled request frames stalled the live flow");
}
