use super::*;

#[tokio::test]
async fn non_200_download_failure_is_typed_and_retained_for_every_mode() {
    for mode in [
        XhttpMode::Auto,
        XhttpMode::PacketUp,
        XhttpMode::StreamUp,
        XhttpMode::StreamOne,
    ] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(32).await;
            let owner = peer.runtime(mode, 32);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let mut download = peer.next().await;
            let _upload = if mode == XhttpMode::StreamUp {
                Some(peer.next().await)
            } else {
                None
            };
            response(&mut download.respond, 403, true);
            for _ in 0..2 {
                let error = stream.read(&mut [0; 1]).await.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                assert!(error.to_string().contains("HTTP 403"));
                assert!(
                    !crate::group::ScoreOutcome::from_io_error(&error).is_node_failure(),
                    "HTTP status is request-scoped"
                );
                let causal = anyhow::Error::new(error);
                assert!(
                    causal
                        .chain()
                        .any(|cause| cause.downcast_ref::<StatusFailure>().is_some())
                );
            }
            let error = stream.write(b"rejected").await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert!(error.to_string().contains("HTTP 403"));
            assert!(stream.flush().await.is_err());
            drop(stream);
            wait_released(&runtime).await;
        })
        .await
        .unwrap_or_else(|_| panic!("retained status failure stalled for {mode:?}"));
    }
}

#[tokio::test]
async fn shutdown_waits_for_split_upload_status_and_retains_late_failure() {
    for mode in [XhttpMode::PacketUp, XhttpMode::StreamUp] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(32).await;
            let owner = peer.runtime(mode, 32);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let _download = peer.next().await;
            stream.write_all(b"accepted").await.unwrap();
            let upload = async {
                let mut upload = peer.next().await;
                assert_eq!(receive(upload.request.body_mut(), 8).await, b"accepted");
                upload
            };
            let (flushed, mut upload) = tokio::join!(stream.flush(), upload);
            flushed.unwrap();
            let mut shutdown = Box::pin(stream.shutdown());
            tokio::select! {
                result = &mut shutdown => panic!("shutdown discarded the upload status: {result:?}"),
                () = eof(upload.request.body_mut()) => {}
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
                    .await
                    .is_err(),
                "shutdown completed before the terminal POST response for {mode:?}"
            );
            response(&mut upload.respond, 503, true);
            let error = shutdown.await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert!(!crate::group::ScoreOutcome::from_io_error(&error).is_node_failure());
            assert!(
                anyhow::Error::new(error)
                    .chain()
                    .any(|cause| cause.downcast_ref::<StatusFailure>().is_some())
            );
            assert!(stream.shutdown().await.unwrap_err().to_string().contains("HTTP 503"));
            drop(stream);
            wait_released(&runtime).await;
        })
        .await
        .unwrap_or_else(|_| panic!("late upload status stalled for {mode:?}"));
    }
}

#[tokio::test]
async fn upload_non_200_interrupts_pending_download_and_is_retained() {
    for mode in [XhttpMode::PacketUp, XhttpMode::StreamUp] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(32).await;
            let owner = peer.runtime(mode, 32);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let _download = peer.next().await;
            let upload = async {
                let mut upload = peer.next().await;
                if mode == XhttpMode::PacketUp {
                    assert_eq!(receive(upload.request.body_mut(), 3).await, b"bad");
                }
                response(&mut upload.respond, 503, true);
            };
            let client = async {
                stream.write_all(b"bad").await.unwrap();
                for _ in 0..2 {
                    let error = stream.read(&mut [0; 1]).await.unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                    assert!(error.to_string().contains("HTTP 503"));
                }
                assert!(
                    stream
                        .flush()
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("HTTP 503")
                );
            };
            tokio::join!(upload, client);
        })
        .await
        .expect("upload status did not wake pending reader");
    }
}

#[tokio::test]
async fn stream_one_status_reaches_flush_without_a_reader_poll() {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = Peer::new(1).await;
        let owner = peer.runtime(XhttpMode::StreamOne, 97);
        let runtime = owner.runtime();
        let mut stream = open(&runtime).await;
        let mut request = peer.next().await;
        peer.wait_settings(&runtime).await;
        stream.write_all(&[0x22; 97]).await.unwrap();
        let first = request.request.body_mut().data().await.unwrap().unwrap();
        assert_eq!(first.len(), 1);
        response(&mut request.respond, 429, true);
        for _ in 0..2 {
            let error = stream.flush().await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert!(error.to_string().contains("HTTP 429"));
        }
        assert!(
            stream
                .write(b"never-replayed")
                .await
                .unwrap_err()
                .to_string()
                .contains("HTTP 429")
        );
    })
    .await
    .expect("stream-one status required a reader to wake the blocked writer");
}

#[tokio::test]
async fn buffered_download_precedes_upload_status_failure() {
    for (mode, download_end) in [
        (XhttpMode::PacketUp, false),
        (XhttpMode::PacketUp, true),
        (XhttpMode::StreamUp, false),
        (XhttpMode::StreamUp, true),
    ] {
        tokio::time::timeout(DEADLINE, async {
            let mut peer = Peer::new(32).await;
            let owner = peer.runtime(mode, 32);
            let runtime = owner.runtime();
            let mut stream = open(&runtime).await;
            let mut download = peer.next().await;
            let mut upload = if mode == XhttpMode::StreamUp {
                Some(peer.next().await)
            } else {
                None
            };
            let mut reply = response(&mut download.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"buffered"), download_end).await;
            let mut first = [0; 1];
            stream.read_exact(&mut first).await.unwrap();
            assert_eq!(first, [b'b']);
            if mode == XhttpMode::PacketUp {
                stream.write_all(b"bad").await.unwrap();
                upload = Some(peer.next().await);
            }
            response(&mut upload.as_mut().unwrap().respond, 502, true);
            loop {
                match stream.write(&[]).await {
                    Ok(0) => tokio::task::yield_now().await,
                    Ok(_) => panic!("empty write accepted payload"),
                    Err(error) => {
                        assert!(error.to_string().contains("HTTP 502"));
                        break;
                    }
                }
            }
            let mut remainder = [0; 7];
            stream.read_exact(&mut remainder).await.unwrap();
            assert_eq!(&remainder, b"uffered");
            for _ in 0..2 {
                let error = stream.read(&mut [0; 1]).await.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
                assert!(error.to_string().contains("HTTP 502"));
            }
        })
        .await
        .expect("upload failure discarded already-owned download payload");
    }
}
