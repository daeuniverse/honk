use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn read_head(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 256];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let size = stream.read(&mut chunk).await.unwrap();
        assert_ne!(size, 0);
        head.extend_from_slice(&chunk[..size]);
    }
    head
}

#[tokio::test]
async fn direct_urltest_routes_the_full_requested_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut wrong, _) = listener.accept().await.unwrap();
        let request = read_head(&mut wrong).await;
        assert!(request.starts_with(b"HEAD /wrong?probe=1 HTTP/1.1\r\n"));
        wrong
            .write_all(b"HTTP/1.1 500 Wrong Target\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();

        let (mut correct, _) = listener.accept().await.unwrap();
        let expected_host = format!("Host: {addr}\r\n");
        for _ in 0..2 {
            let request = read_head(&mut correct).await;
            assert!(request.starts_with(b"HEAD /requested?probe=1 HTTP/1.1\r\n"));
            assert!(
                request
                    .windows(expected_host.len())
                    .any(|part| part == expected_host.as_bytes())
            );
            correct
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
    });
    let node = honk_config::Config::builtin_direct_node();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    let handler = crate::proxy::direct::DirectHandler::new();
    assert!(
        urltest_node(
            &runtime,
            &handler,
            &format!("http://{addr}/wrong?probe=1"),
            Duration::from_secs(2),
        )
        .await
        .is_err()
    );
    urltest_node(
        &runtime,
        &handler,
        &format!("http://{addr}/requested?probe=1"),
        Duration::from_secs(2),
    )
    .await
    .expect("direct URLTest must route the requested path, query, and authority");
    server.await.unwrap();
}

#[tokio::test]
async fn native_request_normalizes_query_only_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let head = read_head(&mut stream).await;
            assert!(
                !head
                    .windows(b"PRIVATE".len())
                    .any(|part| part == b"PRIVATE")
            );
            let response = if head.starts_with(b"HEAD /?check=1 HTTP/1.1\r\n") {
                b"HTTP/1.1 204 No Content\r\n\r\n".as_slice()
            } else {
                b"HTTP/1.1 503 Wrong Target\r\n\r\n".as_slice()
            };
            if stream.write_all(response).await.is_err() {
                break;
            }
        }
    });
    let node = honk_config::Config::builtin_direct_node();
    let mut guard = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
    let request = http::Request::builder()
        .method("HEAD")
        .uri(format!("http://u:PRIVATE@{addr}?check=1"))
        .body(())
        .unwrap();
    let result = measure_http_probe(
        &guard.runtime(),
        &crate::proxy::direct::DirectHandler::new(),
        &request,
        addr,
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        None,
    )
    .await;
    guard.close().await.unwrap();
    peer.abort();
    let _ = peer.await;
    assert!(result.is_ok(), "native request target rejected: {result:?}");
}
