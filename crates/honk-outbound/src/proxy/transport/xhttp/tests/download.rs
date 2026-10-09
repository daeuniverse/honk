use super::*;

/// The node's own download view is TLS-only; tests substitute a cleartext download node.
fn split(
    upload: &Peer,
    download: &Peer,
    mode: XhttpMode,
) -> (EphemeralRuntimeGuard, Arc<XhttpRuntime>) {
    let endpoint = |peer: &Peer| {
        let mut node = node(mode, 32);
        node.address = peer.address.ip().to_string();
        node.port = peer.address.port();
        node
    };
    let mut upload_node = endpoint(upload);
    upload_node.normalize_stream_transport().unwrap();
    upload_node.id = upload_node.derive_id();
    let mut download_node = endpoint(download);
    let options = download_node
        .transport_mut()
        .unwrap()
        .xhttp
        .as_mut()
        .unwrap();
    options.host = Some("download.example".into());
    options.path = "/down/".into();
    download_node.normalize_stream_transport().unwrap();
    let transport = XhttpRuntime::with_download(&upload_node, Some(download_node));
    (
        EphemeralRuntimeGuard::with_xhttp(&upload_node, transport.clone()),
        transport,
    )
}

#[tokio::test]
async fn warm_retire_and_shutdown_reach_the_download_peer() {
    tokio::time::timeout(DEADLINE, async {
        let upload_peer = Peer::new(32).await;
        let download_peer = Peer::new(32).await;
        for retire in [false, true] {
            let (owner, transport) = split(&upload_peer, &download_peer, XhttpMode::PacketUp);
            let runtime = owner.runtime();
            XhttpRuntime::warm(&runtime, DEADLINE).await.unwrap();
            for pool in transport.pools() {
                assert_eq!(pool.live_session_count(), 1);
                assert!(pool.has_usable_session());
            }
            if retire {
                transport.retire();
            } else {
                drop(owner);
            }
            for pool in transport.pools() {
                assert!(pool.is_retired(), "retire={retire}");
            }
        }
    })
    .await
    .expect("split-peer warm stalled");
}

#[tokio::test]
async fn get_reaches_only_the_download_peer_and_supplied_socket_stays_upload() {
    for mode in [XhttpMode::PacketUp, XhttpMode::StreamUp] {
        tokio::time::timeout(DEADLINE, async {
            let mut upload_peer = Peer::new(32).await;
            let mut download_peer = Peer::new(32).await;
            let (owner, transport) = split(&upload_peer, &download_peer, mode);
            let runtime = owner.runtime();
            let supplied = TcpStream::connect(upload_peer.address).await.unwrap();
            let (mut stream, preparation) = transport
                .prepare(&runtime, Some(supplied), DEADLINE)
                .await
                .unwrap();
            let mut get = download_peer.next().await;
            assert_eq!(get.request.method(), http::Method::GET);
            assert_eq!(
                get.request.uri().authority().unwrap().as_str(),
                "download.example"
            );
            let session = get
                .request
                .uri()
                .path()
                .strip_prefix("/down/")
                .unwrap()
                .to_owned();
            uuid::Uuid::parse_str(&session).unwrap();

            stream.write_all(b"up").await.unwrap();
            stream.flush().await.unwrap();
            let mut post = upload_peer.next().await;
            assert_eq!(post.request.method(), http::Method::POST);
            let expected = match mode {
                XhttpMode::PacketUp => format!("{WIRE_PREFIX}{session}/0"),
                _ => format!("{WIRE_PREFIX}{session}"),
            };
            assert_eq!(post.request.uri().path(), expected);
            assert_eq!(receive(post.request.body_mut(), 2).await, b"up");
            response(&mut post.respond, 200, false);
            let mut reply = response(&mut get.respond, 200, false);
            send(&mut reply, Bytes::from_static(b"down"), false).await;
            let mut received = [0; 4];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"down");

            preparation.commit().unwrap();
            assert_eq!(transport.pool.live_session_count(), 1);
            assert_eq!(
                transport
                    .pools()
                    .map(|pool| pool.live_session_count())
                    .sum::<usize>(),
                2
            );
            drop(stream);
        })
        .await
        .unwrap_or_else(|_| panic!("split {mode:?} exchange stalled"));
    }
}

#[tokio::test]
async fn dead_download_carrier_fails_commit_without_publishing_either_peer() {
    tokio::time::timeout(DEADLINE, async {
        let upload_peer = Peer::new(32).await;
        let mut download_peer = Peer::new(32).await;
        let (owner, transport) = split(&upload_peer, &download_peer, XhttpMode::StreamUp);
        let runtime = owner.runtime();
        let (mut stream, preparation) = transport.prepare(&runtime, None, DEADLINE).await.unwrap();
        download_peer.next().await;
        drop(download_peer);
        assert!(stream.read(&mut [0; 1]).await.is_err());
        assert!(preparation.commit().is_err());
        drop(stream);
        for pool in transport.pools() {
            assert_eq!(pool.live_session_count(), 0);
        }
    })
    .await
    .expect("dead download carrier stalled the preparation");
}
