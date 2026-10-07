use super::*;

#[tokio::test]
async fn packet_flush_coalesces_datagrams_during_post_pacing() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(4096).await;
        let owner = peer.runtime(XhttpMode::PacketUp, 4096);
        let mut node = (*owner.runtime().node).clone();
        node.transport_mut()
            .unwrap()
            .xhttp
            .as_mut()
            .unwrap()
            .sc_min_posts_interval_ms = XhttpRange { min: 200, max: 200 };
        node.id = node.derive_id();
        let owner = NodeRuntime::try_ephemeral_guarded(&node).unwrap();
        let runtime = owner.runtime();
        let mut stream = open(&runtime).await;
        let mut download = peer.next().await;
        response(&mut download.respond, 200, false);
        let started = tokio::time::Instant::now();
        stream.write_all(&[0; 32]).await.unwrap();
        let mut first = tokio::time::timeout(Duration::from_millis(100), peer.next())
            .await
            .expect("idle upload waited for an extra batch delay");
        let first_at = tokio::time::Instant::now();
        assert_eq!(receive(first.request.body_mut(), 32).await, [0; 32]);
        eof(first.request.body_mut()).await;
        response(&mut first.respond, 200, true);
        let client = async {
            for value in 1..13u8 {
                stream.write_all(&[value; 32]).await.unwrap();
                stream.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
            stream.shutdown().await.unwrap();
        };
        let server = async {
            let mut received = vec![0; 32];
            let mut posts = 1;
            let mut last = Some(first_at);
            while received.len() < 13 * 32 {
                let mut post = peer.next().await;
                let now = tokio::time::Instant::now();
                if let Some(last) = last {
                    assert!(now.duration_since(last) >= Duration::from_millis(195));
                }
                last = Some(now);
                let length = post.request.headers()["content-length"]
                    .to_str()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                received.extend(receive(post.request.body_mut(), length).await);
                eof(post.request.body_mut()).await;
                response(&mut post.respond, 200, true);
                posts += 1;
            }
            assert_eq!(
                received,
                (0..13u8).flat_map(|value| [value; 32]).collect::<Vec<_>>()
            );
            posts
        };
        let ((), posts) = tokio::join!(client, server);
        eprintln!(
            "packet flush loop: {posts} POSTs in {:?}",
            started.elapsed()
        );
        assert!(posts <= 3, "per-datagram flush serialized paced POSTs");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_posts_aggregate_and_pipeline_without_waiting_for_prior_response() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(2).await;
        let owner = peer.runtime(XhttpMode::PacketUp, 4);
        let runtime = owner.runtime();
        let mut stream = open(&runtime).await;
        let mut download = peer.next().await;
        let path = session_path(&download.request);
        let mut held = Vec::new();
        for seq in 0..MAX_PIPELINE {
            // These individually accepted writes must aggregate into one bounded POST.
            stream.write_all(b"a").await.unwrap();
            stream.write_all(b"b").await.unwrap();
            stream.write_all(b"cd").await.unwrap();
            let client = stream.flush();
            let server = async {
                let mut post = peer.next().await;
                assert_eq!(post.request.uri().path(), format!("{path}/{seq}"));
                assert_eq!(post.request.headers()["content-length"], "4");
                assert_eq!(receive(post.request.body_mut(), 4).await, b"abcd");
                eof(post.request.body_mut()).await;
                post
            };
            let (flushed, post) = tokio::join!(client, server);
            flushed.unwrap();
            held.push(post);
        }
        assert_eq!(
            runtime.xhttp.as_ref().unwrap().pool.metrics().streams,
            MAX_PIPELINE + 1
        );
        stream.write_all(b"last").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.write(b"blocked"))
                .await
                .is_err(),
            "unanswered POST bound did not apply backpressure"
        );
        assert!(
            peer.requests.try_recv().is_err(),
            "pipeline admitted an extra POST"
        );
        response(&mut held[0].respond, 200, true);
        let client = stream.flush();
        let server = async {
            let mut post = peer.next().await;
            assert_eq!(post.request.uri().path(), format!("{path}/{MAX_PIPELINE}"));
            assert_eq!(receive(post.request.body_mut(), 4).await, b"last");
            eof(post.request.body_mut()).await;
            response(&mut post.respond, 200, true);
        };
        let (flushed, ()) = tokio::join!(client, server);
        flushed.unwrap();
        for post in held.iter_mut().skip(1) {
            response(&mut post.respond, 200, true);
        }
        stream.shutdown().await.unwrap();
        let mut reply = response(&mut download.respond, 200, false);
        send(&mut reply, Bytes::from_static(b"complete"), true).await;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"complete");
        assert!(
            peer.requests.try_recv().is_err(),
            "packet shutdown invented an EOF POST"
        );
        drop(stream);
        wait_released(&runtime).await;
    })
    .await
    .expect("packet aggregation/pipeline exchange stalled");
}

#[tokio::test]
async fn split_reader_and_writer_keep_independent_wakeups_under_small_windows() {
    for mode in [
        XhttpMode::PacketUp,
        XhttpMode::StreamUp,
        XhttpMode::StreamOne,
    ] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(31).await;
            let owner = peer.runtime(mode, 257);
            let runtime = owner.runtime();
            let stream = open(&runtime).await;
            let mut download = peer.next().await;
            let path = download.request.uri().path().to_owned();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut reply = response(&mut download.respond, 200, false);
            let payload = Bytes::from(vec![0x37; 8193]);
            let (writer_done, writer_release) = oneshot::channel();
            let (reader_done, reader_release) = oneshot::channel();
            let server = async {
                let receive_upload = async {
                    if mode == XhttpMode::StreamOne {
                        assert_eq!(
                            receive(download.request.body_mut(), 8193).await,
                            vec![0x37; 8193]
                        );
                        eof(download.request.body_mut()).await;
                    } else if mode == XhttpMode::StreamUp {
                        let mut upload = peer.next().await;
                        assert_eq!(
                            receive(upload.request.body_mut(), 8193).await,
                            vec![0x37; 8193]
                        );
                        eof(upload.request.body_mut()).await;
                        response(&mut upload.respond, 200, true);
                    } else {
                        let mut received = Vec::new();
                        let mut seq = 0;
                        while received.len() < 8193 {
                            let mut upload = peer.next().await;
                            assert_eq!(upload.request.uri().path(), format!("{path}/{seq}"));
                            let length: usize = upload.request.headers()["content-length"]
                                .to_str()
                                .unwrap()
                                .parse()
                                .unwrap();
                            assert!(length <= 257);
                            received.extend(receive(upload.request.body_mut(), length).await);
                            response(&mut upload.respond, 200, true);
                            seq += 1;
                        }
                        assert_eq!(received, vec![0x37; 8193]);
                    }
                };
                let send_download = async {
                    for _ in 0..33 {
                        send(&mut reply, Bytes::from(vec![0x83; 257]), false).await;
                    }
                    send(&mut reply, Bytes::from_static(b"tail"), true).await;
                };
                tokio::join!(receive_upload, send_download);
                let _ = writer_done.send(());
                let _ = reader_done.send(());
            };
            let mut clients = JoinSet::new();
            clients.spawn(async move {
                writer.write_all(&payload).await.unwrap();
                writer.flush().await.unwrap();
                writer.shutdown().await.unwrap();
                writer_release
                    .await
                    .expect("peer stopped before upload response completion");
            });
            clients.spawn(async move {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await.unwrap();
                let mut expected = vec![0x83; 33 * 257];
                expected.extend_from_slice(b"tail");
                assert_eq!(received, expected);
                reader_release
                    .await
                    .expect("peer stopped before both response halves completed");
            });
            tokio::join!(server, async {
                while let Some(result) = clients.join_next().await {
                    result.unwrap();
                }
            });
        })
        .await
        .unwrap_or_else(|_| panic!("split wakeups stalled for {mode:?}"));
    }
}

#[tokio::test]
async fn flush_waits_for_real_peer_window_capacity_in_streaming_modes() {
    for mode in [XhttpMode::StreamUp, XhttpMode::StreamOne] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(1).await;
            let owner = peer.runtime(mode, 97);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let mut download = peer.next().await;
            let mut upload = if mode == XhttpMode::StreamUp {
                Some(peer.next().await)
            } else {
                None
            };
            peer.wait_settings(&runtime).await;
            stream.write_all(&[0x49; 97]).await.unwrap();
            let body = match &mut upload {
                Some(upload) => upload.request.body_mut(),
                None => download.request.body_mut(),
            };
            let first = body.data().await.unwrap().unwrap();
            assert!(first.iter().all(|byte| *byte == 0x49));
            assert!(!first.is_empty() && first.len() < 97);
            let remaining = 97 - first.len();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), stream.flush())
                    .await
                    .is_err(),
                "flush acknowledged bytes still held behind the peer's one-byte window"
            );
            body.flow_control().release_capacity(first.len()).unwrap();
            let server = async {
                let body = match &mut upload {
                    Some(upload) => upload.request.body_mut(),
                    None => download.request.body_mut(),
                };
                assert_eq!(receive(body, remaining).await, vec![0x49; remaining]);
                eof(body).await;
                if let Some(upload) = &mut upload {
                    response(&mut upload.respond, 200, true);
                }
            };
            let client = async {
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
            };
            tokio::join!(server, client);
            let mut reply = response(&mut download.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"window-released"), true).await;
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"window-released");
        })
        .await
        .unwrap_or_else(|_| panic!("physical flush accounting stalled for {mode:?}"));
    }
}

#[tokio::test]
async fn settings_window_reduction_keeps_pending_flush_honest_during_other_flow_progress() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(64).await;
        let owner = peer.runtime(XhttpMode::StreamOne, 97);
        let runtime = owner.runtime();
        let stream = open(&runtime).await;
        let mut first = peer.next().await;
        peer.wait_settings(&runtime).await;
        let (mut reader, mut writer) = tokio::io::split(stream);
        writer.write_all(&[0x6a; 97]).await.unwrap();
        let held = receive_without_releasing(first.request.body_mut(), 64).await;
        assert_eq!(held, vec![0x6a; 64]);
        let (flushed, mut flush_result) = oneshot::channel();
        let mut writers = JoinSet::new();
        writers.spawn(async move {
            writer.flush().await.unwrap();
            flushed.send(()).unwrap();
            writer.shutdown().await.unwrap();
        });
        let (ack, applied) = oneshot::channel();
        first
            .control
            .send(PeerCommand::Window(1, ack))
            .await
            .unwrap();
        applied.await.unwrap();
        let mut first_reply = response(&mut first.respond, 200, false);
        send(&mut first_reply, Bytes::from_static(b"reduced"), false).await;
        let mut reduced = [0; 7];
        reader.read_exact(&mut reduced).await.unwrap();
        assert_eq!(&reduced, b"reduced");
        let mut second_stream = open(&runtime).await;
        let mut second = peer.next().await;
        assert_eq!(second.carrier, first.carrier);
        let mut second_reply = response(&mut second.respond, 200, false);
        send(
            &mut second_reply,
            Bytes::from_static(b"other-flow-progress"),
            true,
        )
        .await;
        let mut received = Vec::new();
        second_stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"other-flow-progress");
        assert!(
            matches!(
                flush_result.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "another flow's physical I/O acknowledged the blocked first upload"
        );
        first
            .request
            .body_mut()
            .flow_control()
            .release_capacity(held.len())
            .unwrap();
        let byte = first.request.body_mut().data().await.unwrap().unwrap();
        assert_eq!(
            byte.as_ref(),
            &[0x6a],
            "SETTINGS reduction was not applied to the existing stream"
        );
        assert!(
            matches!(
                flush_result.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "flush acknowledged the bytes still blocked by the reduced window"
        );
        first
            .request
            .body_mut()
            .flow_control()
            .release_capacity(byte.len())
            .unwrap();
        let drain_upload = async {
            assert_eq!(receive(first.request.body_mut(), 32).await, vec![0x6a; 32]);
            eof(first.request.body_mut()).await;
        };
        tokio::join!(drain_upload, async {
            flush_result.await.unwrap();
            while let Some(result) = writers.join_next().await {
                result.unwrap();
            }
        });
        send(&mut first_reply, Bytes::from_static(b"finished"), true).await;
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"finished");
    })
    .await
    .expect("dynamic SETTINGS reduction confused independent-flow physical flush accounting");
}
