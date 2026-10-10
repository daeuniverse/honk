use super::*;

struct PinnedHandler {
    addr: SocketAddr,
    delay: Duration,
}

#[async_trait::async_trait]
impl TcpOutbound for PinnedHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        assert_eq!(target, self.addr);
        assert_eq!(target_domain, None);
        tokio::time::sleep(self.delay).await;
        let stream = tokio::net::TcpStream::connect(target).await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: None,
        })
    }
}

#[tokio::test]
async fn native_http1_cold_and_warm_keep_pinned_authority_without_redirects() {
    for cold in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let methods: &[&str] = if cold { &["GET"] } else { &["HEAD", "GET"] };
            for method in methods {
                let wire = String::from_utf8(read_request_head(&mut stream).await).unwrap();
                assert!(
                    wire.starts_with(&format!("{method} /ready/../check?raw=%2f HTTP/1.1\r\n"))
                );
                assert!(wire.contains("\r\nHost: probe.example:8080\r\n"));
                if *method == "HEAD" {
                    tokio::time::sleep(Duration::from_millis(60)).await;
                }
                stream
                    .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere.invalid/\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let mut guard =
            crate::runtime::NodeRuntime::try_ephemeral_guarded(&make_node("native-wire")).unwrap();
        let request =
            http_probe_request("http://probe.example:8080/ready/../check?raw=%2f", "GET").unwrap();
        let handler = PinnedHandler {
            addr,
            delay: Duration::from_millis(60),
        };
        let started = Instant::now();
        let measured = measure_pinned_http_probe(
            &guard.runtime(),
            &handler,
            &request,
            addr,
            cold,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        if cold {
            assert!(measured.latency >= handler.delay);
        } else {
            assert!(measured.latency + handler.delay <= started.elapsed());
        }
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        guard.close().await.unwrap();
    }
}

#[tokio::test]
async fn native_http1_rejects_invalid_responses_but_keeps_validated_close_fallback() {
    let valid = b"HTTP/1.1 204 No Content\r\n\r\n".as_slice();
    let bad_status = b"HTTP/1.1 500 Internal Server Error\r\n\r\n".as_slice();
    for (cold, responses, succeeds) in [
        (true, vec![bad_status], false),
        (false, vec![bad_status], false),
        (false, vec![valid, bad_status], false),
        (
            false,
            vec![valid, b"HTTP/1.1 204 OK\r\ninvalid\r\n\r\n"],
            false,
        ),
        (false, vec![valid, b"HTTP/1.1 204 OK\r\nPartial: "], false),
        (false, vec![valid], true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for response in responses {
                read_request_head(&mut stream).await;
                stream.write_all(response).await.unwrap();
            }
        });
        let mut guard =
            crate::runtime::NodeRuntime::try_ephemeral_guarded(&make_node("native-invalid"))
                .unwrap();
        let request = http_probe_request("http://probe.example/check", "GET").unwrap();
        let result = measure_pinned_http_probe(
            &guard.runtime(),
            &MockHandler,
            &request,
            addr,
            cold,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(result.is_ok(), succeeds, "cold={cold}: {result:?}");
        peer.await.unwrap();
        guard.close().await.unwrap();
    }
}

#[tokio::test]
async fn http_probe_drop_releases_connection_before_return() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (received, receiving) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await
            .unwrap();
        read_request_head(&mut stream).await;
        received.send(()).unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    });
    let mut guard =
        crate::runtime::NodeRuntime::try_ephemeral_guarded(&make_node("native-cancel")).unwrap();
    let runtime = guard.runtime();
    let request = http_probe_request("http://probe.example/check", "GET").unwrap();
    let mut probe = Box::pin(measure_pinned_http_probe(
        &runtime,
        &MockHandler,
        &request,
        addr,
        false,
        Duration::from_secs(5),
    ));
    tokio::select! {
        result = &mut probe => panic!("probe completed before drop: {result:?}"),
        result = receiving => result.unwrap(),
    }
    drop(probe);
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    guard.close().await.unwrap();
}

#[tokio::test]
async fn native_https_keeps_request_sni_on_pinned_dial() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let hello = tokio_rustls::LazyConfigAcceptor::new(
            tokio_rustls::rustls::server::Acceptor::default(),
            stream,
        )
        .await
        .unwrap();
        assert_eq!(hello.client_hello().server_name(), Some("probe.example"));
        assert!(
            hello
                .client_hello()
                .alpn()
                .unwrap()
                .any(|protocol| protocol == b"h2")
        );
    });
    let mut guard =
        crate::runtime::NodeRuntime::try_ephemeral_guarded(&make_node("native-sni")).unwrap();
    let request = http_probe_request("https://probe.example:8443/check", "GET").unwrap();
    let result = measure_pinned_http_probe(
        &guard.runtime(),
        &PinnedHandler {
            addr,
            delay: Duration::ZERO,
        },
        &request,
        addr,
        true,
        Duration::from_secs(2),
    )
    .await;
    assert!(result.is_err(), "peer intentionally does not complete TLS");
    peer.await.unwrap();
    guard.close().await.unwrap();
}

#[cfg(feature = "owned-tasks")]
#[test]
fn native_cold_runtime_preserves_admission_and_generation_carrier_ceiling() {
    let node = make_node("native-runtime");
    let (generation, _) = crate::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
        std::slice::from_ref(&node),
        1,
        1,
        1,
        false,
        None,
    )
    .unwrap();
    let guard = generation.try_ephemeral_guarded(&node).unwrap();
    let held = generation
        .get(&node.id)
        .unwrap()
        .acquire_vless_carrier()
        .unwrap();
    let error = guard.runtime().acquire_vless_carrier().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crate::proxy::PacketRejection>(),
        Some(crate::proxy::PacketRejection::Capacity)
    ));
    drop(held);
    drop(guard.runtime().acquire_vless_carrier().unwrap());
    let mut stale = node;
    stale.port = 8443;
    assert!(matches!(
        generation.try_ephemeral_guarded(&stale),
        Err(crate::runtime::RuntimeRegistryError::Admission(_))
    ));
}
