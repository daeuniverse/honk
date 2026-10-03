use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn read_request(socket: &mut TcpStream) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
    }
}

fn subscription(listener: &TcpListener) -> Subscription {
    Subscription {
        url: format!("http://{}", listener.local_addr().unwrap()),
        ..Default::default()
    }
}

async fn peer_eof(socket: &mut TcpStream) {
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "pause acknowledgement requires actual socket closure, not only dropping the request future"
    );
}

#[tokio::test]
async fn completed_request_leaves_no_keepalive_before_pause() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let network = Arc::new(SubscriptionNetwork::new().unwrap());
    network.ready().await.unwrap();
    let sub = subscription(&listener);
    let requester = Arc::clone(&network);
    let fetch = tokio::spawn(async move { requester.fetch(&sub).await });
    let (mut socket, _) = listener.accept().await.unwrap();
    read_request(&mut socket).await;
    socket
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
        .await
        .unwrap();
    assert_eq!(fetch.await.unwrap().unwrap(), b"body");
    // The marked client owns one connection per request and keeps no idle pool.
    peer_eof(&mut socket).await;
    network.pause().await.unwrap();
    assert!(network.fetch(&subscription(&listener)).await.is_err());
}

#[tokio::test]
async fn pause_cancels_incomplete_response_and_backpressured_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let network = Arc::new(SubscriptionNetwork::new().unwrap());
    network.ready().await.unwrap();
    let mut requests = JoinSet::new();
    for _ in 0..MAX_REQUESTS * 3 {
        let requester = Arc::clone(&network);
        let sub = subscription(&listener);
        requests.spawn(async move { requester.fetch(&sub).await });
    }
    let mut sockets = Vec::new();
    for _ in 0..MAX_REQUESTS {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
            .await
            .unwrap();
        sockets.push(socket);
    }
    network.pause().await.unwrap();
    while let Some(result) = requests.join_next().await {
        assert!(result.unwrap().is_err());
    }
    for mut socket in sockets {
        let error = tokio::time::timeout(Duration::from_secs(1), socket.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
        ));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "queued work must not open a socket after pause"
    );
}

struct BlockingResolver {
    entered: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    released: parking_lot::Mutex<std::sync::mpsc::Receiver<()>>,
    finished: AtomicBool,
}

async fn held_resolver() -> (
    Arc<SubscriptionNetwork>,
    Arc<BlockingResolver>,
    std::sync::mpsc::Sender<()>,
    JoinHandle<anyhow::Result<Vec<u8>>>,
) {
    let (entered, started) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let resolver = Arc::new(BlockingResolver {
        entered: parking_lot::Mutex::new(Some(entered)),
        released: parking_lot::Mutex::new(released),
        finished: AtomicBool::new(false),
    });
    let owned = Arc::clone(&resolver);
    let network = Arc::new(
        SubscriptionNetwork::with_client(move || {
            // The marked client resolves without a hook, so hold a started
            // blocking job on the network runtime directly.
            tokio::task::spawn_blocking(move || {
                owned.entered.lock().take().unwrap().send(()).unwrap();
                owned.released.lock().recv().unwrap();
                owned.finished.store(true, Ordering::Release);
            });
            crate::marked_http::Client::new()
        })
        .unwrap(),
    );
    network.ready().await.unwrap();
    let requester = Arc::clone(&network);
    let fetch = tokio::spawn(async move {
        requester
            .fetch(&Subscription {
                url: "http://owned-resolver.invalid/".into(),
                ..Default::default()
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started)
        .await
        .unwrap()
        .unwrap();
    (network, resolver, release, fetch)
}

#[tokio::test]
async fn started_blocking_resolver_is_joined_after_cancelled_pause_waiter() {
    let (network, resolver, release, fetch) = held_resolver().await;
    let mut pause = Box::pin(network.pause());
    assert!(futures::poll!(pause.as_mut()).is_pending());
    drop(pause);
    assert!(
        fetch.await.unwrap().is_err(),
        "request cancellation is not resolver completion"
    );
    assert!(!resolver.finished.load(Ordering::Acquire));
    let mut again = Box::pin(network.pause());
    assert!(futures::poll!(again.as_mut()).is_pending());
    release.send(()).unwrap();
    again.await.unwrap();
    assert!(resolver.finished.load(Ordering::Acquire));
}

#[tokio::test]
async fn overdue_actual_join_is_sticky_even_after_cancelled_waiter() {
    let (network, resolver, release, fetch) = held_resolver().await;
    let mut pause = Box::pin(network.pause());
    assert!(futures::poll!(pause.as_mut()).is_pending());
    drop(pause);
    network.state.lock().await.stopped_at =
        Some(Instant::now() - JOIN_DEADLINE - Duration::from_secs(1));
    release.send(()).unwrap();
    assert!(network.pause().await.is_err());
    assert!(resolver.finished.load(Ordering::Acquire));
    assert!(fetch.await.unwrap().is_err());
    assert!(network.pause().await.is_err());
}

#[tokio::test]
async fn network_thread_panic_cannot_be_reported_as_a_successful_pause() {
    let network =
        SubscriptionNetwork::with_client(|| panic!("injected network thread panic")).unwrap();
    assert!(network.ready().await.is_err());
    assert!(network.pause().await.is_err());
    assert!(network.pause().await.is_err());
}
